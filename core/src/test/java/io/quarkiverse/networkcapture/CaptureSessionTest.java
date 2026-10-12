package io.quarkiverse.networkcapture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CaptureSessionTest {

    @TempDir
    Path dir;

    // A handle that produces one packet per poll, without touching the network.
    static class FakeHandle implements CaptureHandle {
        final AtomicInteger polls = new AtomicInteger();
        volatile boolean closed;

        public CaptureInterface networkInterface() {
            return CaptureInterface.builder().name("fake0").index(99).build();
        }

        public LinkType linkType() {
            return LinkType.RAW;
        }

        public int snapLen() {
            return 100;
        }

        public int fd() {
            return -1;
        }

        public int poll(Duration timeout, Consumer<Packet> sink) {
            int n = polls.incrementAndGet();
            if (n > 3) {
                try {
                    Thread.sleep(timeout.toMillis());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return 0;
            }
            sink.accept(Packet.builder().timestampNanos(1_000_000_000L * n).data(new byte[] { 0x45, 0, 0, 0, (byte) n }).build());
            return 1;
        }

        public void close() {
            closed = true;
        }
    }

    private static PacketFilter withHold(PacketFilter filter, Duration hold) {
        return new PacketFilter() {
            @Override
            public boolean accept(CapturedPacket packet) {
                return filter.accept(packet);
            }

            @Override
            public Duration hold() {
                return hold;
            }
        };
    }

    private static long packets(CaptureSession session) {
        return session.stats().stream().mapToLong(CaptureSession.InterfaceStats::packets).sum();
    }

    @Test
    void notifiesListenersAndWritesFile() throws Exception {
        FakeHandle handle = new FakeHandle();
        Path file = dir.resolve("out.pcapng");
        List<Packet> seen = new CopyOnWriteArrayList<>();
        try (CaptureSession session = CaptureSession.start(List.of(handle), file)) {
            session.addListener(captured -> {
                assertEquals("fake0", captured.networkInterface().name());
                assertEquals(LinkType.RAW, captured.linkType());
                seen.add(captured.packet());
            });
            session.addListener(captured -> {
                throw new IllegalStateException("listeners must not break the capture");
            });
            long deadline = System.currentTimeMillis() + 5000;
            while (packets(session) < 3 && System.currentTimeMillis() < deadline) {
                Thread.sleep(20);
            }
            assertEquals(3, packets(session));
        }
        assertTrue(handle.closed);
        // listeners were added after start, so they may have missed the first packets, but not seen extra ones
        assertTrue(seen.size() <= 3);
        assertEquals(3, TestPcapng.parse(Files.readAllBytes(file)).stream().filter(b -> b.type() == 6).count());
    }

    // A handle that produces one packet per poll, forever.
    static final class BusyHandle extends FakeHandle {
        @Override
        public int poll(Duration timeout, Consumer<Packet> sink) {
            try {
                Thread.sleep(20);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            sink.accept(Packet.builder().data(new byte[] { 0x45, 0, 0, 0, 1 }).build());
            return 1;
        }
    }

    @Test
    void flushesTheFileWhileTheQueueIsNeverEmpty() throws Exception {
        Path file = dir.resolve("busy.pcapng");
        try (CaptureSession session = CaptureSession.start(List.of(new BusyHandle()), file, withHold(p -> true, Duration.ofMillis(300)))) {
            long deadline = System.currentTimeMillis() + 5000;
            while (Files.size(file) == 0 && System.currentTimeMillis() < deadline) {
                Thread.sleep(50);
            }
            assertTrue(Files.size(file) > 0, "the file must be readable while the capture runs");
            assertTrue(packets(session) > 0);
        }
    }

    @Test
    void appliesFilterAndCountsFilteredPackets() throws Exception {
        FakeHandle handle = new FakeHandle();
        Path file = dir.resolve("filtered.pcapng");
        PacketFilter dropSecond = captured -> captured.packet().data()[4] != 2;
        List<Packet> seen = new CopyOnWriteArrayList<>();
        try (CaptureSession session = CaptureSession.start(List.of(handle), file, withHold(dropSecond, Duration.ofMillis(50)))) {
            session.addListener(captured -> seen.add(captured.packet()));
            long deadline = System.currentTimeMillis() + 5000;
            while (packets(session) + session.stats().get(0).filtered() < 3 && System.currentTimeMillis() < deadline) {
                Thread.sleep(20);
            }
            CaptureSession.InterfaceStats stats = session.stats().get(0);
            assertEquals(2, stats.packets());
            assertEquals(1, stats.filtered());
            assertEquals(0, stats.dropped());
        }
        assertEquals(2, seen.size(), "listeners only see accepted packets");
        assertEquals(2, TestPcapng.parse(Files.readAllBytes(file)).stream().filter(b -> b.type() == 6).count());
    }
}
