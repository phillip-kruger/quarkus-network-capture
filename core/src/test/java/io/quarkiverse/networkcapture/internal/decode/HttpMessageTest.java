package io.quarkiverse.networkcapture.internal.decode;

import static io.quarkiverse.networkcapture.TestPackets.concat;
import static io.quarkiverse.networkcapture.TestPackets.ethernet;
import static io.quarkiverse.networkcapture.TestPackets.ipv4;
import static io.quarkiverse.networkcapture.TestPackets.tcp;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import io.quarkiverse.networkcapture.LinkType;

class HttpMessageTest {

    private static final byte[] LO = { 127, 0, 0, 1 };

    private static HttpMessage decode(int sport, int dport, String payload) {
        return decode(sport, dport, payload.getBytes(StandardCharsets.UTF_8));
    }

    private static HttpMessage decode(int sport, int dport, byte[] payload) {
        PacketSummary s = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800), ipv4(6, LO, LO, 20 + payload.length),
                tcp(sport, dport, 0x18), payload));
        assertEquals("HTTP", s.protocol());
        return s.http();
    }

    @Test
    void requestWithHeadersAndBody() {
        HttpMessage m = decode(50000, 8080,
                "POST /api/items?x=1 HTTP/1.1\r\nHost: localhost:8080\r\nContent-Type: application/json\r\n"
                        + "Content-Length: 12\r\n\r\n{\"name\":\"a\"}");
        assertTrue(m.isRequest());
        assertEquals("POST", m.method());
        assertEquals("/api/items?x=1", m.target());
        assertEquals("HTTP/1.1", m.version());
        assertEquals("http://localhost:8080/api/items?x=1", m.url());
        assertEquals(3, m.headers().size());
        assertEquals("application/json", m.header("content-type"));
        assertEquals(12, m.contentLength());
        assertEquals("{\"name\":\"a\"}", m.bodyAsText(1000));
        assertTrue(m.bodyComplete());
    }

    @Test
    void responseWithPartialBody() {
        HttpMessage m = decode(8080, 50000, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nonly the start");
        assertFalse(m.isRequest());
        assertEquals(200, m.status());
        assertEquals("OK", m.reason());
        assertNull(m.url());
        assertEquals(14, m.body().length);
        assertFalse(m.bodyComplete());
        assertEquals("only the", m.bodyAsText(8));
    }

    @Test
    void binaryBodyIsNotText() {
        byte[] head = "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
        byte[] png = { (byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0 };
        HttpMessage m = decode(8080, 50000, concat(head, png));
        assertEquals(10, m.body().length);
        assertNull(m.bodyAsText(1000));
    }

    @Test
    void headersCutBySegmentGiveNoMessage() {
        HttpMessage m = decode(50000, 8080, "GET /hello HTTP/1.1\r\nHost: localhost\r\nAccept: */*");
        assertNull(m);
    }

    @Test
    void absoluteTargetIsTheUrl() {
        HttpMessage m = decode(50000, 3128, "GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assertEquals("http://example.com/x", m.url());
        assertEquals("", m.bodyAsText(10));
    }
}
