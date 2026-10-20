package io.quarkiverse.networkcapture.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.smallrye.common.os.OS;

class LibcTest {

    // FIONREAD: _IOR('f', 127, int) on macOS, a fixed number on Linux
    private static final long FIONREAD = OS.LINUX.isCurrent() ? 0x541BL : 0x4004667FL;

    @TempDir
    Path dir;

    // ioctl is variadic; on macOS arm64 variadic arguments travel on the stack, so a binding that passes the pointer
    // like a fixed argument hands the kernel garbage.
    @Test
    void ioctlPassesItsPointerArgument() {
        Path socketPath = dir.resolve("s");
        byte[] payload = "hello".getBytes(StandardCharsets.UTF_8);
        int receiver = UnixSockets.bind(socketPath);
        int sender = UnixSockets.socket();
        try (Arena arena = Arena.ofConfined()) {
            UnixSockets.send(sender, socketPath, payload, new int[0]);

            MemorySegment available = arena.allocate(ValueLayout.JAVA_INT);
            int result = Libc.ioctl(receiver, FIONREAD, available);
            assertEquals(0, result, "ioctl(FIONREAD) failed: " + Libc.errno());
            assertTrue(available.get(ValueLayout.JAVA_INT, 0) >= payload.length,
                    "FIONREAD reported " + available.get(ValueLayout.JAVA_INT, 0) + " bytes");
        } finally {
            UnixSockets.close(sender);
            UnixSockets.close(receiver);
            Libc.unlink(socketPath.toString());
        }
    }
}
