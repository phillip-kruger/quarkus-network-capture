package io.quarkiverse.networkcapture;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.FileInputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import java.util.Objects;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import io.quarkiverse.networkcapture.internal.Libc;
import io.quarkiverse.networkcapture.internal.UnixSockets;


class UnixSocketsTest {

    @TempDir
    Path dir;

    @Test
    void passesFileDescriptorsBetweenSockets() throws Exception {
        Path file = dir.resolve("payload.txt");
        Files.writeString(file, "hello from the other side");
        Path socketPath = dir.resolve("test.sock");

        int receiver = UnixSockets.bind(socketPath);
        int sender = UnixSockets.socket();
        int fileFd = Libc.open(file.toString(), 0);
        try {
            assertNull(UnixSockets.receive(receiver, Duration.ofMillis(50)), "nothing sent yet");

            UnixSockets.send(sender, socketPath, "OK lo 1 65535".getBytes(StandardCharsets.UTF_8), new int[] { fileFd });
            UnixSockets.send(sender, socketPath, "DONE".getBytes(StandardCharsets.UTF_8), new int[0]);

            UnixSockets.Message first = UnixSockets.receive(receiver, Duration.ofSeconds(5));
            assertEquals("OK lo 1 65535", new String(Objects.requireNonNull(first).payload(), StandardCharsets.UTF_8));
            assertEquals(1, first.fds().length);
            int received = first.fds()[0];
            assertEquals(Files.readString(file), readAll(received));
            Libc.close(received);

            UnixSockets.Message second = UnixSockets.receive(receiver, Duration.ofSeconds(5));
            assertArrayEquals("DONE".getBytes(StandardCharsets.UTF_8), Objects.requireNonNull(second).payload());
            assertEquals(0, second.fds().length);
        } finally {
            Libc.close(fileFd);
            UnixSockets.close(sender);
            UnixSockets.close(receiver);
        }
    }

    private static String readAll(int fd) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment buffer = arena.allocate(1024);
            long n = Libc.read(fd, buffer, buffer.byteSize());
            return new String(buffer.asSlice(0, n).toArray(ValueLayout.JAVA_BYTE), StandardCharsets.UTF_8);
        }
    }
}
