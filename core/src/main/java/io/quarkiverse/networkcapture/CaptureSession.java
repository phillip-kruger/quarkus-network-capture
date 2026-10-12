package io.quarkiverse.networkcapture;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.LockSupport;

import io.quarkiverse.networkcapture.internal.PcapngWriter;

/**
 * Reads from one or more {@link CaptureHandle}s on background threads and writes everything to one pcapng file.
 * <p>
 * Packets pass through a queue to a single writer thread, which optionally holds each packet for a while and
 * applies a {@link PacketFilter} before writing it and notifying listeners. Each handle becomes one Interface
 * Description Block and each kept packet one Enhanced Packet Block, see the <a href="https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/">PCAP Next Generation (pcapng) Capture File Format</a>.
 * <p>
 * Threads: one daemon reader thread per handle and one daemon writer thread, started by {@link #start} and ended by
 * {@link #stop()}. The filter and the listeners run on the writer thread; every other method of this class may be
 * called from any thread. See the package documentation for the full threading model.
 */
public final class CaptureSession implements AutoCloseable {

    private static final DateTimeFormatter FILE_TIMESTAMP = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");
    private static final Duration POLL_TIMEOUT = Duration.ofMillis(200);
    private static final int QUEUE_CAPACITY = 1 << 16;
    // Written packets reach the file at least this often, so the file can be read while capturing.
    private static final long FLUSH_INTERVAL_NANOS = Duration.ofMillis(500).toNanos();

    /**
     * Counters of one captured interface.
     */
    public interface InterfaceStats {

        String name();

        /**
         * Packets written to the file.
         */
        long packets();

        /**
         * Captured bytes written to the file.
         */
        long bytes();

        /**
         * Packets rejected by the filter.
         */
        long filtered();

        /**
         * Packets lost because the writer could not keep up.
         */
        long dropped();

        /**
         * The error that stopped reading from this interface, or null.
         */
        String error();
    }

    private record InterfaceStatsImpl(String name, long packets, long bytes, long filtered, long dropped, String error)
            implements InterfaceStats {
    }

    private record Queued(Reader reader, Packet packet, long enqueuedNanos) {
    }


    private final Path file;
    private final PcapngWriter writer;
    private final List<Reader> readers = new ArrayList<>();
    private final Instant startedAt = Instant.now();
    private final List<PacketListener> listeners = new CopyOnWriteArrayList<>();
    private final PacketFilter filter;
    private final long holdNanos;
    private final LinkedBlockingQueue<Queued> queue = new LinkedBlockingQueue<>(QUEUE_CAPACITY);
    private final Thread writerThread;
    private volatile boolean running = true;
    private volatile boolean readersDone;

    private CaptureSession(Path file, List<CaptureHandle> handles, PacketFilter filter) {
        this.file = file;
        this.filter = filter;
        this.holdNanos = filter == null ? 0 : filter.hold().toNanos();
        this.writer = PcapngWriter.create(file, "quarkus-network-capture");
        for (CaptureHandle handle : handles) {
            int id = writer.addInterface(handle.networkInterface().name(), handle.linkType(), handle.snapLen());
            readers.add(new Reader(handle, id));
        }
        writerThread = new Thread(this::writeLoop, "network-capture-writer");
        writerThread.setDaemon(true);
    }

    /**
     * A file name for a new capture in the given directory, {@code capture-<date>-<time>.pcapng}, so that a new
     * capture never overwrites an earlier one.
     */
    public static Path defaultFile(Path directory) {
        return directory.resolve("capture-" + LocalDateTime.now().format(FILE_TIMESTAMP) + ".pcapng");
    }

    /**
     * Starts capturing everything into {@link #defaultFile} in the working directory.
     */
    public static CaptureSession start(List<CaptureHandle> handles) {
        return start(handles, defaultFile(Path.of("")), null);
    }

    /**
     * Starts capturing with a filter into {@link #defaultFile} in the working directory.
     */
    public static CaptureSession start(List<CaptureHandle> handles, PacketFilter filter) {
        return start(handles, defaultFile(Path.of("")), filter);
    }

    /**
     * Starts capturing everything. The session takes ownership of the handles and closes them on {@link #stop()}.
     */
    public static CaptureSession start(List<CaptureHandle> handles, Path file) {
        return start(handles, file, null);
    }

    /**
     * Starts capturing with a filter, which also decides how long packets are held before it sees them.
     *
     * @param filter decides which packets are written, or null for all
     */
    public static CaptureSession start(List<CaptureHandle> handles, Path file, PacketFilter filter) {
        if (handles.isEmpty()) {
            throw new IllegalArgumentException("At least one capture handle is required");
        }
        CaptureSession session = new CaptureSession(file, handles, filter);
        session.writerThread.start();
        for (Reader reader : session.readers) {
            reader.thread.start();
        }
        return session;
    }

    public Path file() {
        return file;
    }

    public Instant startedAt() {
        return startedAt;
    }

    /**
     * Registers a listener that sees every packet after it has been written to the file. Listeners are called on the
     * writer thread, one packet at a time; a listener that throws is ignored and does not stop the capture.
     */
    public void addListener(PacketListener listener) {
        listeners.add(listener);
    }

    public void removeListener(PacketListener listener) {
        listeners.remove(listener);
    }

    public boolean isRunning() {
        return running;
    }

    /**
     * The counters of every captured interface, in the order of the handles the session was started with.
     */
    public List<InterfaceStats> stats() {
        List<InterfaceStats> perInterface = new ArrayList<>();
        for (Reader r : readers) {
            perInterface.add(new InterfaceStatsImpl(r.handle.networkInterface().name(), r.packets.get(), r.bytes.get(),
                    r.filtered.get(), r.dropped.get(), r.error));
        }
        return perInterface;
    }

    /**
     * Stops capturing, writes out what is still queued, and closes handles and file. Blocks until the reader and
     * writer threads have finished. Safe to call from any thread, and more than once.
     */
    public void stop() {
        if (!running) {
            return;
        }
        running = false;
        for (Reader r : readers) {
            join(r.thread);
        }
        readersDone = true;
        join(writerThread);
        for (Reader r : readers) {
            r.handle.close();
        }
    }

    @Override
    public void close() {
        stop();
    }

    private static void join(Thread thread) {
        try {
            thread.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void writeLoop() {
        boolean dirty = true; // the file header is buffered
        long lastFlush = System.nanoTime();
        try {
            while (true) {
                Queued queued = queue.poll(100, TimeUnit.MILLISECONDS);
                if (dirty && System.nanoTime() - lastFlush > FLUSH_INTERVAL_NANOS) {
                    writer.flush();
                    dirty = false;
                    lastFlush = System.nanoTime();
                }
                if (queued == null) {
                    if (readersDone) {
                        break;
                    }
                    continue;
                }
                long wait = queued.enqueuedNanos() + holdNanos - System.nanoTime();
                if (wait > 0) {
                    LockSupport.parkNanos(wait);
                }
                Reader reader = queued.reader();
                Packet packet = queued.packet();
                CapturedPacket captured = new DefaultCapturedPacket(reader.handle.networkInterface(), reader.handle.linkType(), packet);
                if (filter != null && !filter.accept(captured)) {
                    reader.filtered.incrementAndGet();
                } else {
                    writer.writePacket(reader.interfaceId, packet.timestampNanos(), packet.originalLength(), packet.data());
                    dirty = true;
                    reader.packets.incrementAndGet();
                    reader.bytes.addAndGet(packet.data().length);
                    for (PacketListener listener : listeners) {
                        try {
                            listener.onPacket(captured);
                        } catch (RuntimeException ignored) {
                            // a misbehaving listener must not stop the capture
                        }
                    }
                }
                if (dirty && queue.isEmpty()) {
                    writer.flush();
                    dirty = false;
                    lastFlush = System.nanoTime();
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            writer.close();
        }
    }

    private final class Reader {
        final CaptureHandle handle;
        final int interfaceId;
        final Thread thread;
        final AtomicLong packets = new AtomicLong();
        final AtomicLong bytes = new AtomicLong();
        final AtomicLong filtered = new AtomicLong();
        final AtomicLong dropped = new AtomicLong();
        volatile String error;

        Reader(CaptureHandle handle, int interfaceId) {
            this.handle = handle;
            this.interfaceId = interfaceId;
            this.thread = new Thread(this::run, "network-capture-" + handle.networkInterface().name());
            this.thread.setDaemon(true);
        }

        void run() {
            try {
                while (running) {
                    handle.poll(POLL_TIMEOUT, this::enqueue);
                }
            } catch (RuntimeException e) {
                error = e.getMessage();
            }
        }

        private void enqueue(Packet packet) {
            if (!queue.offer(new Queued(this, packet, System.nanoTime()))) {
                dropped.incrementAndGet();
            }
        }
    }
}
