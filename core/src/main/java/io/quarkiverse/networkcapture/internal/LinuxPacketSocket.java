package io.quarkiverse.networkcapture.internal;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.function.Consumer;

import io.smallrye.ffm.Errno;
import io.quarkiverse.networkcapture.Capture;
import io.quarkiverse.networkcapture.CaptureException;
import io.quarkiverse.networkcapture.CaptureInterface;
import io.quarkiverse.networkcapture.CaptureOptions;
import io.quarkiverse.networkcapture.LinkType;
import io.quarkiverse.networkcapture.Packet;

/**
 * Linux capture through an {@code AF_PACKET} socket bound to one interface.
 * <p>
 * This goes through FFM because the JDK has no raw socket API: {@code AF_PACKET}/{@code SOCK_RAW} sockets, the
 * {@code setsockopt} calls for promiscuous mode and timestamps, and the {@code ioctl} for the hardware address are
 * all unreachable from {@code java.net} and NIO.
 * <p>
 * References: <a href="https://man7.org/linux/man-pages/man7/packet.7.html">packet(7)</a> for {@code SOCK_RAW},
 * {@code ETH_P_ALL}, {@code struct sockaddr_ll}, {@code PACKET_ADD_MEMBERSHIP}/{@code PACKET_MR_PROMISC} and
 * {@code PACKET_OUTGOING}; <a href="https://www.kernel.org/doc/html/latest/networking/timestamping.html">Linux
 * timestamping</a> for {@code SO_TIMESTAMPNS} and the {@code SCM_TIMESTAMPNS} control message;
 * <a href="https://man7.org/linux/man-pages/man7/netdevice.7.html">netdevice(7)</a> for {@code SIOCGIFHWADDR}, whose
 * {@code ARPHRD_*} hardware type decides the {@link LinkType};
 * <a href="https://man7.org/linux/man-pages/man7/capabilities.7.html">capabilities(7)</a> for {@code CAP_NET_RAW},
 * which creating the socket requires. The reference implementation this follows, including the mapping of
 * {@code ARPHRD_LOOPBACK} to Ethernet framing and the skipping of outgoing loopback packets that would otherwise
 * appear twice, is libpcap's
 * <a href="https://github.com/the-tcpdump-group/libpcap/blob/master/pcap-linux.c">pcap-linux.c</a>.
 */
public final class LinuxPacketSocket implements NativeCaptureHandle {

    private static final int AF_PACKET = 17;
    private static final int SOCK_RAW = 3;
    private static final int ETH_P_ALL = 0x0003;
    private static final int SO_TIMESTAMPNS = 35;
    private static final int SCM_TIMESTAMPNS = 35;
    private static final int SOL_PACKET = 263;
    private static final int PACKET_ADD_MEMBERSHIP = 1;
    private static final int PACKET_MR_PROMISC = 1;
    private static final int PACKET_OUTGOING = 4;
    private static final int MSG_DONTWAIT = 0x40;
    private static final int MSG_TRUNC = 0x20;
    private static final long SIOCGIFHWADDR = 0x8927;
    private static final int ARPHRD_ETHER = 1;
    private static final int ARPHRD_LOOPBACK = 772;
    private static final int ARPHRD_NONE = 0xFFFE;
    private static final int SOCKADDR_LL_SIZE = 20;
    private static final int IFREQ_SIZE = 40;
    private static final int MAX_BATCH = 256;

    private final int fd;
    private final CaptureInterface networkInterface;
    private final LinkType linkType;
    private final int snapLen;

    private final Arena arena = Arena.ofShared();
    private final MemorySegment pollfd;
    private final Msghdr msghdr;
    private final MemorySegment buffer;
    private final MemorySegment name;
    private final MemorySegment control;
    private volatile boolean closed;

    private LinuxPacketSocket(int fd, CaptureInterface networkInterface, LinkType linkType, int snapLen) {
        this.fd = fd;
        this.networkInterface = networkInterface;
        this.linkType = linkType;
        this.snapLen = snapLen;
        this.pollfd = arena.allocate(Libc.POLLFD_SIZE);
        this.msghdr = new Msghdr(arena);
        this.buffer = arena.allocate(snapLen);
        this.name = arena.allocate(SOCKADDR_LL_SIZE);
        this.control = arena.allocate(Msghdr.cmsgSpace(16), 8);
    }

    public static LinuxPacketSocket open(CaptureInterface networkInterface, CaptureOptions options) {
        int fd = Libc.socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd < 0) {
            throw Libc.failure("socket(AF_PACKET, SOCK_RAW)");
        }
        try (Arena arena = Arena.ofConfined()) {
            LinkType linkType = linkType(hardwareType(fd, networkInterface.name(), arena));

            MemorySegment addr = arena.allocate(SOCKADDR_LL_SIZE);
            addr.set(JAVA_SHORT, 0, (short) AF_PACKET);
            addr.set(JAVA_SHORT, 2, (short) htons(ETH_P_ALL));
            addr.set(JAVA_INT, 4, networkInterface.index());
            if (Libc.bind(fd, addr, SOCKADDR_LL_SIZE) < 0) {
                throw Libc.failure("bind(" + networkInterface.name() + ")");
            }

            if (Libc.setsockopt(fd, Libc.SOL_SOCKET, SO_TIMESTAMPNS, 1) < 0) {
                throw Libc.failure("setsockopt(SO_TIMESTAMPNS)");
            }

            if (options.promiscuous()) {
                MemorySegment mreq = arena.allocate(16);
                mreq.set(JAVA_INT, 0, networkInterface.index());
                mreq.set(JAVA_SHORT, 4, (short) PACKET_MR_PROMISC);
                if (Libc.setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq, 16) < 0) {
                    throw Libc.failure("setsockopt(PACKET_ADD_MEMBERSHIP)");
                }
            }
            return new LinuxPacketSocket(fd, networkInterface, linkType, options.snapLen());
        } catch (RuntimeException e) {
            Libc.close(fd);
            throw e;
        }
    }

    public static LinuxPacketSocket adopt(int fd, CaptureInterface networkInterface, LinkType linkType, int snapLen) {
        return new LinuxPacketSocket(fd, networkInterface, linkType, snapLen);
    }

    private static int hardwareType(int fd, String ifaceName, Arena arena) {
        MemorySegment ifreq = arena.allocate(IFREQ_SIZE);
        byte[] nameBytes = ifaceName.getBytes(StandardCharsets.UTF_8);
        if (nameBytes.length > 15) {
            throw new CaptureException("Interface name too long: " + ifaceName);
        }
        MemorySegment.copy(MemorySegment.ofArray(nameBytes), 0, ifreq, 0, nameBytes.length);
        if (Libc.ioctl(fd, SIOCGIFHWADDR, ifreq) < 0) {
            throw Libc.failure("ioctl(SIOCGIFHWADDR, " + ifaceName + ")");
        }
        return ifreq.get(JAVA_SHORT, 16) & 0xFFFF;
    }

    private static LinkType linkType(int arphrd) {
        return switch (arphrd) {
            case ARPHRD_ETHER, ARPHRD_LOOPBACK -> LinkType.ETHERNET;
            case ARPHRD_NONE -> LinkType.RAW;
            default -> throw new CaptureException("Unsupported interface hardware type: " + arphrd);
        };
    }

    private static int htons(int value) {
        return ByteOrder.nativeOrder() == ByteOrder.BIG_ENDIAN ? value : Short.toUnsignedInt(Short.reverseBytes((short) value));
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
        int count = 0;
        while (count < MAX_BATCH) {
            msghdr.setName(name, SOCKADDR_LL_SIZE);
            msghdr.setData(buffer, snapLen);
            msghdr.setControl(control, control.byteSize());
            msghdr.setFlags(0);
            long n = Libc.recvmsg(fd, msghdr.segment(), MSG_DONTWAIT | MSG_TRUNC);
            if (n < 0) {
                Errno errno = Libc.errno();
                if (errno == Errno.EAGAIN) {
                    break;
                }
                if (errno == Errno.EINTR) {
                    continue;
                }
                throw Libc.failure("recvmsg");
            }
            // Loopback traffic is seen on the way out and again on the way in; keep one copy, like libpcap does.
            if (networkInterface.loopback() && name.get(JAVA_BYTE, 10) == PACKET_OUTGOING) {
                continue;
            }
            int capLen = (int) Math.min(n, snapLen);
            byte[] data = buffer.asSlice(0, capLen).toArray(JAVA_BYTE);
            sink.accept(Packet.builder().timestampNanos(timestamp()).originalLength((int) n).data(data).build());
            count++;
        }
        return count;
    }

    private long timestamp() {
        long controlLen = msghdr.controlLen();
        long off = 0;
        Msghdr.Cmsg cmsg;
        while ((cmsg = Msghdr.readCmsg(control, off, controlLen)) != null) {
            if (cmsg.level() == Libc.SOL_SOCKET && cmsg.type() == SCM_TIMESTAMPNS && cmsg.dataLen() >= 16) {
                long sec = control.get(JAVA_LONG, cmsg.dataOffset());
                long nsec = control.get(JAVA_LONG, cmsg.dataOffset() + 8);
                return sec * 1_000_000_000L + nsec;
            }
            off = cmsg.next();
        }
        Instant now = Instant.now();
        return now.getEpochSecond() * 1_000_000_000L + now.getNano();
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
