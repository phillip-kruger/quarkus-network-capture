package io.quarkiverse.networkcapture.internal;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.function.Consumer;

import io.smallrye.ffm.Errno;
import io.quarkiverse.networkcapture.Capture;
import io.quarkiverse.networkcapture.CaptureException;
import io.quarkiverse.networkcapture.CaptureInterface;
import io.quarkiverse.networkcapture.CaptureOptions;
import io.quarkiverse.networkcapture.CapturePermissionException;
import io.quarkiverse.networkcapture.LinkType;
import io.quarkiverse.networkcapture.Packet;

/**
 * macOS capture through a {@code /dev/bpf*} device.
 * <p>
 * This goes through FFM because, while the device could be opened and read as a plain file from Java, it captures
 * nothing until it is configured with {@code BIOC*} ioctls, and the JDK has no {@code ioctl}.
 * <p>
 * References: <a href="https://man.freebsd.org/cgi/man.cgi?bpf%284%29">bpf(4)</a> for the device semantics, the
 * {@code BIOC*} ioctls and the {@code struct bpf_hdr} record format with {@code BPF_WORDALIGN} padding;
 * Apple's <a href="https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/bpf.h">xnu bsd/net/bpf.h</a>
 * for the exact ioctl encodings used here and for {@code BPF_TIMEVAL}, which makes the record timestamp two 32 bit
 * fields on 64 bit macOS; the reference implementation is libpcap's
 * <a href="https://github.com/the-tcpdump-group/libpcap/blob/master/pcap-bpf.c">pcap-bpf.c</a>, which this follows
 * in setting the buffer length before attaching the interface and in installing a {@code ret #snaplen} filter.
 */
public final class MacOsBpf implements NativeCaptureHandle {

    private static final int O_RDONLY = 0;
    private static final int O_RDWR = 2;
    private static final int MAX_DEVICES = 256;
    private static final int IFREQ_SIZE = 32;
    private static final int REQUESTED_BUFFER = 1 << 20;

    // _IOC(inout, group, num, len) = inout | ((len & 0x1fff) << 16) | (group << 8) | num, group 'B' = 0x42
    private static final long BIOCGBLEN = 0x40044266L; // _IOR('B', 102, u_int)
    private static final long BIOCSBLEN = 0xC0044266L; // _IOWR('B', 102, u_int)
    private static final long BIOCSETF = 0x80104267L; // _IOW('B', 103, struct bpf_program)
    private static final long BIOCPROMISC = 0x20004269L; // _IO('B', 105)
    private static final long BIOCGDLT = 0x4004426AL; // _IOR('B', 106, u_int)
    private static final long BIOCSETIF = 0x8020426CL; // _IOW('B', 108, struct ifreq)
    private static final long BIOCIMMEDIATE = 0x80044270L; // _IOW('B', 112, u_int)

    private static final int DLT_NULL = 0;
    private static final int DLT_EN10MB = 1;
    private static final int DLT_RAW = 12;

    private static final int BPF_RET_K = 0x06;

    private final int fd;
    private final CaptureInterface networkInterface;
    private final LinkType linkType;
    private final int snapLen;
    private final int bufferSize;

    private final Arena arena = Arena.ofShared();
    private final MemorySegment pollfd;
    private final MemorySegment buffer;
    private volatile boolean closed;

    private MacOsBpf(int fd, CaptureInterface networkInterface, LinkType linkType, int snapLen, int bufferSize) {
        this.fd = fd;
        this.networkInterface = networkInterface;
        this.linkType = linkType;
        this.snapLen = snapLen;
        this.bufferSize = bufferSize;
        this.pollfd = arena.allocate(Libc.POLLFD_SIZE);
        this.buffer = arena.allocate(bufferSize, 8);
    }

    public static MacOsBpf open(CaptureInterface networkInterface, CaptureOptions options) {
        int fd = openDevice();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment uint = arena.allocate(JAVA_INT);

            // Buffer length must be set before the interface is attached
            uint.set(JAVA_INT, 0, REQUESTED_BUFFER);
            if (Libc.ioctl(fd, BIOCSBLEN, uint) < 0) {
                throw Libc.failure("ioctl(BIOCSBLEN)");
            }
            if (Libc.ioctl(fd, BIOCGBLEN, uint) < 0) {
                throw Libc.failure("ioctl(BIOCGBLEN)");
            }
            int bufferSize = uint.get(JAVA_INT, 0);

            MemorySegment ifreq = arena.allocate(IFREQ_SIZE);
            byte[] nameBytes = networkInterface.name().getBytes(StandardCharsets.UTF_8);
            if (nameBytes.length > 15) {
                throw new CaptureException("Interface name too long: " + networkInterface.name());
            }
            MemorySegment.copy(MemorySegment.ofArray(nameBytes), 0, ifreq, 0, nameBytes.length);
            if (Libc.ioctl(fd, BIOCSETIF, ifreq) < 0) {
                throw Libc.failure("ioctl(BIOCSETIF, " + networkInterface.name() + ")");
            }

            uint.set(JAVA_INT, 0, 1);
            if (Libc.ioctl(fd, BIOCIMMEDIATE, uint) < 0) {
                throw Libc.failure("ioctl(BIOCIMMEDIATE)");
            }

            if (options.promiscuous() && Libc.ioctl(fd, BIOCPROMISC, MemorySegment.NULL) < 0) {
                throw Libc.failure("ioctl(BIOCPROMISC)");
            }

            // Accept-everything filter whose return value sets the snap length: "ret #snapLen"
            MemorySegment insn = arena.allocate(8, 8);
            insn.set(JAVA_SHORT, 0, (short) BPF_RET_K);
            insn.set(JAVA_INT, 4, options.snapLen());
            MemorySegment program = arena.allocate(16, 8);
            program.set(JAVA_INT, 0, 1);
            program.set(ADDRESS, 8, insn);
            if (Libc.ioctl(fd, BIOCSETF, program) < 0) {
                throw Libc.failure("ioctl(BIOCSETF)");
            }

            if (Libc.ioctl(fd, BIOCGDLT, uint) < 0) {
                throw Libc.failure("ioctl(BIOCGDLT)");
            }
            LinkType linkType = linkType(uint.get(JAVA_INT, 0));
            return new MacOsBpf(fd, networkInterface, linkType, options.snapLen(), bufferSize);
        } catch (RuntimeException e) {
            Libc.close(fd);
            throw e;
        }
    }

    public static MacOsBpf adopt(int fd, CaptureInterface networkInterface, LinkType linkType, int snapLen) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment uint = arena.allocate(JAVA_INT);
            if (Libc.ioctl(fd, BIOCGBLEN, uint) < 0) {
                throw Libc.failure("ioctl(BIOCGBLEN)");
            }
            return new MacOsBpf(fd, networkInterface, linkType, snapLen, uint.get(JAVA_INT, 0));
        }
    }

    private static int openDevice() {
        boolean permissionDenied = false;
        for (int i = 0; i < MAX_DEVICES; i++) {
            String path = "/dev/bpf" + i;
            int fd = Libc.open(path, O_RDWR);
            if (fd < 0 && Libc.errno() == Errno.EACCES) {
                fd = Libc.open(path, O_RDONLY);
            }
            if (fd >= 0) {
                return fd;
            }
            Errno errno = Libc.errno();
            if (errno == Errno.EBUSY) {
                continue;
            }
            if (errno == Errno.EACCES || errno == Errno.EPERM) {
                permissionDenied = true;
                continue;
            }
            if (errno == Errno.ENOENT) {
                break;
            }
            throw Libc.failure("open(" + path + ")");
        }
        if (permissionDenied) {
            throw new CapturePermissionException("Permission denied opening /dev/bpf*. Install Wireshark's ChmodBPF "
                    + "or run the capture helper with elevated privileges.");
        }
        throw new CaptureException("No free /dev/bpf device found");
    }

    private static LinkType linkType(int dlt) {
        return switch (dlt) {
            case DLT_NULL -> LinkType.NULL;
            case DLT_EN10MB -> LinkType.ETHERNET;
            case DLT_RAW -> LinkType.RAW;
            default -> throw new CaptureException("Unsupported data link type: " + dlt);
        };
    }

    @Override
    public CaptureInterface networkInterface() {
        return networkInterface;
    }

    @Override
    public LinkType linkType() {
        return linkType;
    }

    @Override
    public int snapLen() {
        return snapLen;
    }

    @Override
    public int fd() {
        return fd;
    }

    @Override
    public int poll(Duration timeout, Consumer<Packet> sink) {
        if (closed) {
            throw new CaptureException("Capture handle is closed");
        }
        int ready = Libc.pollIn(pollfd, fd, (int) timeout.toMillis());
        if (ready < 0) {
            if (Libc.errno() == Errno.EINTR) {
                return 0;
            }
            throw Libc.failure("poll");
        }
        if (ready == 0) {
            return 0;
        }
        long n = Libc.read(fd, buffer, bufferSize);
        if (n < 0) {
            Errno errno = Libc.errno();
            if (errno == Errno.EAGAIN || errno == Errno.EINTR) {
                return 0;
            }
            throw Libc.failure("read(bpf)");
        }
        // Each record: struct bpf_hdr { timeval32 bh_tstamp; u32 bh_caplen; u32 bh_datalen; u16 bh_hdrlen; }
        int count = 0;
        long off = 0;
        while (off + 18 <= n) {
            long sec = Integer.toUnsignedLong(buffer.get(JAVA_INT, off));
            long usec = Integer.toUnsignedLong(buffer.get(JAVA_INT, off + 4));
            int capLen = buffer.get(JAVA_INT, off + 8);
            int dataLen = buffer.get(JAVA_INT, off + 12);
            int hdrLen = buffer.get(JAVA_SHORT, off + 16) & 0xFFFF;
            if (off + hdrLen + capLen > n) {
                break;
            }
            byte[] data = buffer.asSlice(off + hdrLen, capLen).toArray(JAVA_BYTE);
            sink.accept(Packet.builder().timestampNanos(sec * 1_000_000_000L + usec * 1_000L).originalLength(dataLen).data(data).build());
            count++;
            off += (hdrLen + capLen + 3) & ~3L;
        }
        return count;
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        Libc.close(fd);
        arena.close();
    }
}
