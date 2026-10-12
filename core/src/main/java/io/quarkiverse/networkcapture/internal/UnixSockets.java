package io.quarkiverse.networkcapture.internal;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;

import io.smallrye.common.os.OS;
import io.smallrye.ffm.Errno;
import io.quarkiverse.networkcapture.CaptureException;

/**
 * Unix domain datagram sockets with {@code SCM_RIGHTS} file descriptor passing.
 * Datagrams keep message and descriptor boundaries intact, which stream sockets do not guarantee portably.
 * <p>
 * This goes through FFM rather than {@link java.net.UnixDomainSocketAddress} because the JDK's Unix domain socket
 * support only offers {@code SOCK_STREAM} channels with plain read/write: there is no API for ancillary data, so
 * {@code SCM_RIGHTS} descriptor passing, which is the whole reason this socket exists, cannot be done with it.
 * <p>
 * References: <a href="https://man7.org/linux/man-pages/man7/unix.7.html">unix(7)</a> for {@code struct sockaddr_un}
 * (Linux: 2 byte family then a 108 byte path; macOS: 1 byte length, 1 byte family, 104 byte path) and the
 * {@code SCM_RIGHTS} ancillary message; <a href="https://man7.org/linux/man-pages/man3/cmsg.3.html">cmsg(3)</a>
 * for the control message layout.
 */
public final class UnixSockets {

    private UnixSockets() {
    }

    private static final boolean LINUX = OS.LINUX.isCurrent();
    private static final int SOCKADDR_UN_SIZE = LINUX ? 110 : 106;
    private static final int PATH_OFFSET = 2;
    private static final int MAX_PATH = SOCKADDR_UN_SIZE - PATH_OFFSET - 1;
    private static final int MAX_FDS = 16;
    private static final int MAX_PAYLOAD = 4096;

    public record Message(byte[] payload, int[] fds) {
    }

    private static MemorySegment sockaddr(Arena arena, Path path) {
        byte[] bytes = path.toString().getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_PATH) {
            throw new CaptureException("Unix socket path too long: " + path);
        }
        MemorySegment addr = arena.allocate(SOCKADDR_UN_SIZE);
        if (LINUX) {
            addr.set(JAVA_SHORT, 0, (short) Libc.AF_UNIX);
        } else {
            addr.set(JAVA_BYTE, 0, (byte) SOCKADDR_UN_SIZE);
            addr.set(JAVA_BYTE, 1, (byte) Libc.AF_UNIX);
        }
        MemorySegment.copy(MemorySegment.ofArray(bytes), 0, addr, PATH_OFFSET, bytes.length);
        return addr;
    }

    // Creates a datagram socket bound to path. The caller must close it and unlink the path.
    public static int bind(Path path) {
        int fd = socket();
        try (Arena arena = Arena.ofConfined()) {
            if (Libc.bind(fd, sockaddr(arena, path), SOCKADDR_UN_SIZE) < 0) {
                CaptureException e = Libc.failure("bind(" + path + ")");
                Libc.close(fd);
                throw e;
            }
        }
        return fd;
    }

    // Creates an unbound datagram socket for sending.
    public static int socket() {
        int fd = Libc.socket(Libc.AF_UNIX, Libc.SOCK_DGRAM, 0);
        if (fd < 0) {
            throw Libc.failure("socket(AF_UNIX)");
        }
        return fd;
    }

    public static void send(int socket, Path to, byte[] payload, int[] fds) {
        if (fds.length > MAX_FDS || payload.length > MAX_PAYLOAD) {
            throw new IllegalArgumentException("message too large");
        }
        try (Arena arena = Arena.ofConfined()) {
            Msghdr msg = new Msghdr(arena);
            msg.setName(sockaddr(arena, to), SOCKADDR_UN_SIZE);
            MemorySegment data = arena.allocateFrom(JAVA_BYTE, payload);
            msg.setData(data, payload.length);
            if (fds.length > 0) {
                long dataLen = (long) fds.length * JAVA_INT.byteSize();
                long space = Msghdr.cmsgSpace(dataLen);
                MemorySegment control = arena.allocate(space, 8);
                long off = Msghdr.writeCmsg(control, 0, Libc.SOL_SOCKET, Libc.SCM_RIGHTS, dataLen);
                for (int i = 0; i < fds.length; i++) {
                    control.set(JAVA_INT, off + i * JAVA_INT.byteSize(), fds[i]);
                }
                msg.setControl(control, space);
            }
            long sent = Libc.sendmsg(socket, msg.segment(), 0);
            if (sent < 0) {
                throw Libc.failure("sendmsg(" + to + ")");
            }
        }
    }

    /**
     * Waits for one datagram.
     *
     * @return the message, or null when {@code timeout} elapsed
     */
    public static Message receive(int socket, Duration timeout) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment pollfd = arena.allocate(Libc.POLLFD_SIZE);
            int ready = Libc.pollIn(pollfd, socket, (int) timeout.toMillis());
            if (ready < 0) {
                if (Libc.errno() == Errno.EINTR) {
                    return null;
                }
                throw Libc.failure("poll");
            }
            if (ready == 0) {
                return null;
            }
            Msghdr msg = new Msghdr(arena);
            MemorySegment data = arena.allocate(MAX_PAYLOAD);
            msg.setData(data, MAX_PAYLOAD);
            long controlSize = Msghdr.cmsgSpace((long) MAX_FDS * JAVA_INT.byteSize());
            MemorySegment control = arena.allocate(controlSize, 8);
            msg.setControl(control, controlSize);
            long n = Libc.recvmsg(socket, msg.segment(), 0);
            if (n < 0) {
                throw Libc.failure("recvmsg");
            }
            byte[] payload = data.asSlice(0, n).toArray(JAVA_BYTE);
            int[] fds = new int[0];
            long controlLen = msg.controlLen();
            long off = 0;
            Msghdr.Cmsg cmsg;
            while ((cmsg = Msghdr.readCmsg(control, off, controlLen)) != null) {
                if (cmsg.level() == Libc.SOL_SOCKET && cmsg.type() == Libc.SCM_RIGHTS) {
                    int count = (int) (cmsg.dataLen() / JAVA_INT.byteSize());
                    fds = new int[count];
                    for (int i = 0; i < count; i++) {
                        fds[i] = control.get(JAVA_INT, cmsg.dataOffset() + i * JAVA_INT.byteSize());
                    }
                }
                off = cmsg.next();
            }
            return new Message(payload, fds);
        }
    }

    public static void close(int fd) {
        Libc.close(fd);
    }
}
