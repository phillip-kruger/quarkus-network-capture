package io.quarkiverse.networkcapture.internal.decode;

import static io.quarkiverse.networkcapture.TestPackets.captured;
import static io.quarkiverse.networkcapture.TestPackets.concat;
import static io.quarkiverse.networkcapture.TestPackets.ethernet;
import static io.quarkiverse.networkcapture.TestPackets.ipv4;
import static io.quarkiverse.networkcapture.TestPackets.tcp;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

class HttpRequestFilterTest {

    private static final byte[] SERVER = { 10, 0, 0, 1 };
    private static final byte[] CLIENT = { 10, 0, 0, 2 };

    private final HttpRequestFilter filter = new HttpRequestFilter(target -> target.contains("/dev-ui"));

    private boolean fromClient(String payload) {
        byte[] p = payload.getBytes(StandardCharsets.UTF_8);
        byte[] packet = concat(ethernet(0x0800), ipv4(6, CLIENT, SERVER, 20 + p.length), tcp(50000, 8080, 0x18), p);
        return filter.accept(captured(packet));
    }

    private boolean fromServer(String payload) {
        byte[] p = payload.getBytes(StandardCharsets.UTF_8);
        byte[] packet = concat(ethernet(0x0800), ipv4(6, SERVER, CLIENT, 20 + p.length), tcp(8080, 50000, 0x18), p);
        return filter.accept(captured(packet));
    }

    @Test
    void dropsTheWholeExcludedExchangeAndKeepsTheRest() {
        assertFalse(fromClient("GET /q/dev-ui/devui-data.js?1 HTTP/1.1\r\nHost: localhost\r\n\r\n"));
        assertFalse(fromServer("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n12345"), "the response is dropped");
        assertFalse(fromServer("67890"), "and so is the rest of its body");

        assertTrue(fromClient("GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n"), "an application request on the same connection stays");
        assertTrue(fromServer("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"));

        assertTrue(fromServer("not http at all"), "unrecognised traffic passes");
    }
}
