package io.quarkiverse.networkcapture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;


/**
 * End to end check of opening through the privileged helper. Needs passwordless {@code sudo}, so it is opt in:
 * {@code mvn test -Dpcap.sudo=true}.
 */
@EnabledIfSystemProperty(named = "pcap.sudo", matches = "true")
class ElevatedCaptureSudoTest {

    @TempDir
    Path dir;

    @Test
    void capturesLoopbackTraffic() throws Exception {
        CaptureInterface lo = CaptureInterfaces.list().stream().filter(CaptureInterface::loopback).findFirst().orElseThrow();
        Capture.Result result = Capture.open(List.of(lo),
                CaptureOptions.builder().elevation(Elevation.SUDO).helperTimeout(Duration.ofSeconds(30)).build());
        assertTrue(result.skipped().isEmpty(), result.skipped().toString());
        List<CaptureHandle> handles = result.handles();
        assertEquals(1, handles.size());

        Path file = dir.resolve("lo.pcapng");
        byte[] marker = "QUARKUS-PCAP-MARKER".getBytes(StandardCharsets.UTF_8);
        try (CaptureSession session = CaptureSession.start(handles, file)) {
            try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
                    Socket client = new Socket(InetAddress.getLoopbackAddress(), server.getLocalPort());
                    Socket accepted = server.accept()) {
                OutputStream out = client.getOutputStream();
                out.write(marker);
                out.flush();
                InputStream in = accepted.getInputStream();
                assertEquals(marker.length, in.readNBytes(marker.length).length);
            }
            Thread.sleep(500);
            List<CaptureSession.InterfaceStats> stats = session.stats();
            assertTrue(stats.stream().mapToLong(CaptureSession.InterfaceStats::packets).sum() > 0, "expected packets, got " + stats);
            assertTrue(stats.stream().allMatch(i -> i.error() == null), stats.toString());
        }

        byte[] bytes = Files.readAllBytes(file);
        List<TestPcapng.Block> blocks = TestPcapng.parse(bytes);
        assertTrue(blocks.stream().anyMatch(b -> b.type() == 6 && indexOf(b.body(), marker) >= 0),
                "marker payload not found in capture");
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer: for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
