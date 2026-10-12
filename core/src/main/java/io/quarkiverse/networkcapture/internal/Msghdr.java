package io.quarkiverse.networkcapture.internal;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import io.smallrye.common.os.OS;

/**
 * Platform aware layout of {@code struct msghdr}, {@code struct iovec} and {@code struct cmsghdr}.
 * <p>
 * References: <a href="https://man7.org/linux/man-pages/man2/recvmsg.2.html">recvmsg(2)</a> for {@code struct msghdr}
 * and {@code struct iovec}; <a href="https://man7.org/linux/man-pages/man3/cmsg.3.html">cmsg(3)</a> for the control
 * message header and the {@code CMSG_ALIGN}, {@code CMSG_SPACE} and {@code CMSG_DATA} arithmetic. On Linux
 * {@code msg_iovlen}, {@code msg_controllen} and {@code cmsg_len} are {@code size_t} and control messages are 8 byte
 * aligned; on macOS they are {@code int}/{@code socklen_t} and alignment is 4 bytes.
 */
final class Msghdr {

    private static final boolean LINUX = OS.LINUX.isCurrent();

    static final long SIZE = LINUX ? 56 : 48;
    static final long IOVEC_SIZE = 16;
    static final long CMSG_HEADER = LINUX ? 16 : 12;
    private static final long CMSG_ALIGNMENT = LINUX ? 8 : 4;

    private final MemorySegment segment;
    private final MemorySegment iovec;

    Msghdr(Arena arena) {
        segment = arena.allocate(SIZE, 8);
        iovec = arena.allocate(IOVEC_SIZE, 8);
        segment.set(ADDRESS, 16, iovec);
        setIovLen(1);
    }

    MemorySegment segment() {
        return segment;
    }

    void setName(MemorySegment name, int length) {
        segment.set(ADDRESS, 0, name);
        segment.set(JAVA_INT, 8, length);
    }

    int nameLen() {
        return segment.get(JAVA_INT, 8);
    }

    void setData(MemorySegment buffer, long length) {
        iovec.set(ADDRESS, 0, buffer);
        iovec.set(JAVA_LONG, 8, length);
    }

    private void setIovLen(long n) {
        if (LINUX) {
            segment.set(JAVA_LONG, 24, n);
        } else {
            segment.set(JAVA_INT, 24, (int) n);
        }
    }

    void setControl(MemorySegment control, long length) {
        segment.set(ADDRESS, 32, control);
        setControlLen(length);
    }

    private void setControlLen(long length) {
        if (LINUX) {
            segment.set(JAVA_LONG, 40, length);
        } else {
            segment.set(JAVA_INT, 40, (int) length);
        }
    }

    long controlLen() {
        return LINUX ? segment.get(JAVA_LONG, 40) : segment.get(JAVA_INT, 40);
    }

    int flags() {
        return segment.get(JAVA_INT, LINUX ? 48 : 44);
    }

    void setFlags(int flags) {
        segment.set(JAVA_INT, LINUX ? 48 : 44, flags);
    }

    static long cmsgAlign(long n) {
        return (n + CMSG_ALIGNMENT - 1) & ~(CMSG_ALIGNMENT - 1);
    }

    static long cmsgSpace(long dataLen) {
        return CMSG_HEADER + cmsgAlign(dataLen);
    }

    // Writes a control message header at offset and returns the offset of its data.
    static long writeCmsg(MemorySegment control, long offset, int level, int type, long dataLen) {
        if (LINUX) {
            control.set(JAVA_LONG, offset, CMSG_HEADER + dataLen);
        } else {
            control.set(JAVA_INT, offset, (int) (CMSG_HEADER + dataLen));
        }
        control.set(JAVA_INT, offset + (LINUX ? 8 : 4), level);
        control.set(JAVA_INT, offset + (LINUX ? 12 : 8), type);
        return offset + CMSG_HEADER;
    }

    record Cmsg(int level, int type, long dataOffset, long dataLen, long next) {
    }

    // Reads the control message at offset, or null if none fits in controlLen.
    static Cmsg readCmsg(MemorySegment control, long offset, long controlLen) {
        if (offset + CMSG_HEADER > controlLen) {
            return null;
        }
        long len = LINUX ? control.get(JAVA_LONG, offset) : control.get(JAVA_INT, offset);
        if (len < CMSG_HEADER || offset + len > controlLen) {
            return null;
        }
        int level = control.get(JAVA_INT, offset + (LINUX ? 8 : 4));
        int type = control.get(JAVA_INT, offset + (LINUX ? 12 : 8));
        return new Cmsg(level, type, offset + CMSG_HEADER, len - CMSG_HEADER, offset + cmsgAlign(len));
    }
}
