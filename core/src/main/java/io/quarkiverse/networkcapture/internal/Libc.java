package io.quarkiverse.networkcapture.internal;

import static io.smallrye.ffm.AsType.size_t;
import static io.smallrye.ffm.AsType.ssize_t;
import static io.smallrye.ffm.AsType.stdc_unsigned_int;
import static io.smallrye.ffm.AsType.stdc_unsigned_long;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.invoke.MethodHandle;

import io.smallrye.common.os.OS;
import io.smallrye.ffm.As;
import io.smallrye.ffm.Errno;
import io.smallrye.ffm.ErrnoConsumer;
import io.smallrye.ffm.Link;
import io.quarkiverse.networkcapture.CaptureException;
import io.quarkiverse.networkcapture.CapturePermissionException;

/**
 * Thin libc bindings. Every call returns the raw C result; on failure callers read {@link #errno()}.
 * <p>
 * The {@code native} methods are declared with <a href="https://github.com/smallrye/smallrye-ffm">SmallRye FFM</a>
 * annotations and rewritten at build time into lazily linked downcalls of the
 * <a href="https://openjdk.org/jeps/454">Foreign Function &amp; Memory API</a>. The C types of platform sized
 * arguments are declared with {@code @As}; {@code errno} is delivered to the {@link ErrnoConsumer} parameter after
 * each call and kept per thread.
 * <p>
 * {@code ioctl} and {@code open} are variadic and bound by hand with {@link Linker.Option#firstVariadicArg(int)}:
 * the SmallRye FFM plugin drops {@code @Variadic}, and a variadic call linked as a fixed one crashes on macOS
 * arm64, where variadic arguments are passed on the stack. This is tracked in
 * <a href="https://github.com/smallrye/smallrye-ffm/issues/66">smallrye-ffm#66</a>; once it is fixed, these two
 * should go back to {@code @Link} declarations with {@code @Variadic} like the rest.
 * <p>
 * References: <a href="https://man7.org/linux/man-pages/man2/poll.2.html">poll(2)</a>, noting that {@code nfds_t}
 * is {@code unsigned long} on Linux and {@code unsigned int} on macOS, which is why {@code poll} is declared twice.
 */
public final class Libc {

    private Libc() {
    }

    public static final int AF_UNIX = 1;
    public static final int SOCK_DGRAM = 2;
    public static final int SCM_RIGHTS = 1;
    public static final short POLLIN = 1;
    public static final long POLLFD_SIZE = 8;

    private static final boolean LINUX = OS.LINUX.isCurrent();

    public static final int SOL_SOCKET = LINUX ? 1 : 0xffff;

    private static final class LastErrno implements ErrnoConsumer {
        Errno errno = Errno.SUCCESS;

        @Override
        public void accept(Errno errno) {
            this.errno = errno;
        }
    }

    private static final ThreadLocal<LastErrno> LAST_ERRNO = ThreadLocal.withInitial(LastErrno::new);

    // The errno of the last call on this thread.
    public static Errno errno() {
        return LAST_ERRNO.get().errno;
    }

    // Builds the exception for a failed call, mapping permission errors to CapturePermissionException.
    public static CaptureException failure(String action) {
        Errno errno = errno();
        String message = action + " failed: " + errno.message() + " (" + errno + ")";
        if (errno == Errno.EPERM || errno == Errno.EACCES) {
            return new CapturePermissionException(message);
        }
        return new CaptureException(message);
    }

    @Link
    private static native int socket(int domain, int type, int protocol, ErrnoConsumer errno);

    public static int socket(int domain, int type, int protocol) {
        return socket(domain, type, protocol, LAST_ERRNO.get());
    }

    @Link
    private static native int bind(int fd, MemorySegment addr, @As(stdc_unsigned_int) int addrLen, ErrnoConsumer errno);

    public static int bind(int fd, MemorySegment addr, int addrLen) {
        return bind(fd, addr, addrLen, LAST_ERRNO.get());
    }

    @Link
    private static native int setsockopt(int fd, int level, int option, MemorySegment value,
            @As(stdc_unsigned_int) int valueLen, ErrnoConsumer errno);

    public static int setsockopt(int fd, int level, int option, MemorySegment value, int valueLen) {
        return setsockopt(fd, level, option, value, valueLen, LAST_ERRNO.get());
    }

    public static int setsockopt(int fd, int level, int option, int value) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment v = arena.allocate(JAVA_INT);
            v.set(JAVA_INT, 0, value);
            return setsockopt(fd, level, option, v, (int) JAVA_INT.byteSize());
        }
    }

    @Link
    @As(ssize_t)
    private static native long recvmsg(int fd, MemorySegment msghdr, int flags, ErrnoConsumer errno);

    public static long recvmsg(int fd, MemorySegment msghdr, int flags) {
        return recvmsg(fd, msghdr, flags, LAST_ERRNO.get());
    }

    @Link
    @As(ssize_t)
    private static native long sendmsg(int fd, MemorySegment msghdr, int flags, ErrnoConsumer errno);

    public static long sendmsg(int fd, MemorySegment msghdr, int flags) {
        return sendmsg(fd, msghdr, flags, LAST_ERRNO.get());
    }

    @Link
    @As(ssize_t)
    private static native long read(int fd, MemorySegment buffer, @As(size_t) long length, ErrnoConsumer errno);

    public static long read(int fd, MemorySegment buffer, long length) {
        return read(fd, buffer, length, LAST_ERRNO.get());
    }

    // nfds_t is unsigned long on Linux
    @Link
    private static native int poll(MemorySegment fds, @As(stdc_unsigned_long) long nfds, int timeoutMillis,
            ErrnoConsumer errno);

    // nfds_t is unsigned int on macOS
    @Link
    private static native int poll(MemorySegment fds, @As(stdc_unsigned_int) int nfds, int timeoutMillis,
            ErrnoConsumer errno);

    // Polls a single descriptor for POLLIN. Returns the poll(2) result.
    public static int pollIn(MemorySegment pollfd, int fd, int timeoutMillis) {
        pollfd.set(JAVA_INT, 0, fd);
        pollfd.set(JAVA_SHORT, 4, POLLIN);
        pollfd.set(JAVA_SHORT, 6, (short) 0);
        if (LINUX) {
            return poll(pollfd, 1L, timeoutMillis, LAST_ERRNO.get());
        }
        return poll(pollfd, 1, timeoutMillis, LAST_ERRNO.get());
    }

    @Link
    private static native int close(int fd, ErrnoConsumer errno);

    public static int close(int fd) {
        return close(fd, LAST_ERRNO.get());
    }

    @Link
    private static native int unlink(String path, ErrnoConsumer errno);

    public static int unlink(String path) {
        return unlink(path, LAST_ERRNO.get());
    }

    private static final Linker LINKER = Linker.nativeLinker();
    private static final StructLayout CALL_STATE = Linker.Option.captureStateLayout();
    private static final long ERRNO_OFFSET = CALL_STATE.byteOffset(MemoryLayout.PathElement.groupElement("errno"));

    // int ioctl(int fd, unsigned long request, ...)
    private static final MethodHandle IOCTL = LINKER.downcallHandle(LINKER.defaultLookup().findOrThrow("ioctl"),
            FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_LONG, ADDRESS), Linker.Option.firstVariadicArg(2),
            Linker.Option.captureCallState("errno"));

    // int open(const char *path, int flags, ...)
    private static final MethodHandle OPEN = LINKER.downcallHandle(LINKER.defaultLookup().findOrThrow("open"),
            FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT), Linker.Option.firstVariadicArg(2),
            Linker.Option.captureCallState("errno"));

    public static int ioctl(int fd, long request, MemorySegment arg) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment state = arena.allocate(CALL_STATE);
            int result = (int) IOCTL.invokeExact(state, fd, request, arg);
            LAST_ERRNO.get().accept(Errno.ofNativeValue(state.get(JAVA_INT, ERRNO_OFFSET)));
            return result;
        } catch (Throwable t) {
            throw new CaptureException("ioctl failed", t);
        }
    }

    public static int open(String path, int flags) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment state = arena.allocate(CALL_STATE);
            int result = (int) OPEN.invokeExact(state, arena.allocateFrom(path), flags);
            LAST_ERRNO.get().accept(Errno.ofNativeValue(state.get(JAVA_INT, ERRNO_OFFSET)));
            return result;
        } catch (Throwable t) {
            throw new CaptureException("open failed", t);
        }
    }
}
