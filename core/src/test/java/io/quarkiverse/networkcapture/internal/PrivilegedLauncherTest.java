package io.quarkiverse.networkcapture.internal;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PrivilegedLauncherTest {

    // sockaddr_un leaves 103 bytes for the path on macOS, the tighter of the two supported platforms.
    private static final int MACOS_MAX_SOCKET_PATH = 103;

    // The default macOS per-user temporary directory, e.g. /var/folders/dn/kqytnydj70l9gs07dcfzl0j00000gn/T
    private static final int MACOS_TMPDIR_LENGTH = 49;

    @TempDir
    Path tmp;

    @Test
    void socketPathFitsUnderMacOsTemporaryDirectory() throws Exception {
        int padding = MACOS_TMPDIR_LENGTH - tmp.toString().length() - 1;
        assumeTrue(padding > 0, "temporary directory already longer than the macOS one");
        Path parent = Files.createDirectory(tmp.resolve("x".repeat(padding)));

        Path socketPath = PrivilegedLauncher.createSocketPath(parent);
        try {
            int length = socketPath.toString().getBytes(StandardCharsets.UTF_8).length;
            assertTrue(length <= MACOS_MAX_SOCKET_PATH,
                    socketPath + " is " + length + " bytes, over the macOS limit of " + MACOS_MAX_SOCKET_PATH);
        } finally {
            Files.deleteIfExists(socketPath.getParent());
        }
    }
}
