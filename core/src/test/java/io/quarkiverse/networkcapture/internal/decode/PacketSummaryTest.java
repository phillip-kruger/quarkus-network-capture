package io.quarkiverse.networkcapture.internal.decode;

import static io.quarkiverse.networkcapture.TestPackets.clientHello;
import static io.quarkiverse.networkcapture.TestPackets.concat;
import static io.quarkiverse.networkcapture.TestPackets.ethernet;
import static io.quarkiverse.networkcapture.TestPackets.ipv4;
import static io.quarkiverse.networkcapture.TestPackets.ipv6;
import static io.quarkiverse.networkcapture.TestPackets.tcp;
import static io.quarkiverse.networkcapture.TestPackets.tlsRecord;
import static io.quarkiverse.networkcapture.TestPackets.udp;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;

import org.junit.jupiter.api.Test;
import io.quarkiverse.networkcapture.LinkType;

class PacketSummaryTest {

    @Test
    void ethernetIpv4TcpSyn() {
        byte[] packet = concat(ethernet(0x0800), ipv4(6, new byte[] { 127, 0, 0, 1 }, new byte[] { 10, 0, 0, 2 }, 20),
                tcp(43210, 8080, 0x02));
        PacketSummary s = PacketSummary.decode(LinkType.ETHERNET, packet);
        assertEquals("TCP", s.protocol());
        assertEquals("127.0.0.1:43210", s.source());
        assertEquals("10.0.0.2:8080", s.destination());
        assertEquals("43210 → 8080 [SYN] Seq=7 Len=0", s.info());
        assertEquals(43210, s.sourcePort());
        assertEquals(8080, s.destinationPort());
    }

    @Test
    void httpRequestAndResponse() {
        byte[] lo = { 127, 0, 0, 1 };
        byte[] request = "GET /hello HTTP/1.1\r\nHost: localhost:8080\r\n\r\n".getBytes();
        PacketSummary req = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + request.length), tcp(50000, 8080, 0x18), request));
        assertEquals("HTTP", req.protocol());
        assertEquals("GET /hello HTTP/1.1", req.info());
        assertEquals(8080, req.destinationPort());

        byte[] response = "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello".getBytes();
        PacketSummary res = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + response.length), tcp(8080, 50000, 0x18), response));
        assertEquals("HTTP", res.protocol());
        assertEquals("HTTP/1.1 200 OK", res.info());

        byte[] body = "hello world, this is not a request line\r\n".getBytes();
        PacketSummary data = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + body.length), tcp(8080, 50000, 0x18), body));
        assertEquals("TCP", data.protocol());
        assertEquals("8080 \u2192 50000 [ACK, PSH] Seq=7 Len=" + body.length, data.info());

        byte[] binary = { 0x16, 0x03, 0x01, 0x00, (byte) 0xC8, 0x01, 0x00, 0x00, (byte) 0xC4, 0x03, 0x03, 0x00, 0x00 };
        PacketSummary tls = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + binary.length), tcp(50000, 443, 0x18), binary));
        assertEquals("HTTPS", tls.protocol()); // truncated hello without ALPN, port 443 decides
        assertEquals("Client Hello", tls.info());
    }

    @Test
    void tls() {
        byte[] lo = { 127, 0, 0, 1 };
        byte[] hello = clientHello("localhost", "h2", "http/1.1");
        PacketSummary h = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + hello.length), tcp(50000, 8443, 0x18), hello));
        assertEquals("HTTPS", h.protocol());
        assertEquals("Client Hello (SNI=localhost, ALPN=h2, http/1.1)", h.info());
        assertEquals("localhost", h.tls().serverName());

        // no ALPN: the port decides
        byte[] pg = clientHello("db.internal");
        PacketSummary db = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + pg.length), tcp(50000, 5432, 0x18), pg));
        assertEquals("TLS", db.protocol());
        assertEquals("Client Hello (SNI=db.internal)", db.info());
        PacketSummary web = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + pg.length), tcp(50000, 443, 0x18), pg));
        assertEquals("HTTPS", web.protocol());

        // ALPN that is not HTTP
        byte[] mq = clientHello(null, "mqtt");
        PacketSummary m = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + mq.length), tcp(50000, 8443, 0x18), mq));
        assertEquals("TLS", m.protocol());
        assertEquals("Client Hello (ALPN=mqtt)", m.info());

        // several records in one segment, the last one cut by the segment
        byte[] serverHello = { 2, 0, 0, 4, 3, 3, 0, 0 };
        byte[] reply = concat(tlsRecord(0x16, serverHello), tlsRecord(0x14, new byte[] { 1 }),
                new byte[] { 0x17, 3, 3, 0x10, 0, 1, 2, 3 });
        PacketSummary r = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + reply.length), tcp(8443, 50000, 0x18), reply));
        assertEquals("HTTPS", r.protocol());
        assertEquals("Server Hello, Change Cipher Spec, Application Data", r.info());

        // a valid record header followed by something that is not a record is not TLS
        byte[] fake = concat(tlsRecord(0x17, new byte[] { 1 }), new byte[] { 0x42, 0x42, 0x42, 0x42, 0x42 });
        PacketSummary f = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + fake.length), tcp(8443, 50000, 0x18), fake));
        assertEquals("TCP", f.protocol());
    }

    @Test
    void http2Frames() {
        byte[] lo = { 127, 0, 0, 1 };
        // SETTINGS on stream 0 (6 byte payload) followed by HEADERS on stream 1 with END_HEADERS (4 byte payload)
        byte[] frames = { 0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 100,
                0, 0, 4, 1, 4, 0, 0, 0, 1, (byte) 0x82, (byte) 0x86, (byte) 0x84, 0x41 };
        PacketSummary s = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + frames.length), tcp(50000, 8080, 0x18), frames));
        assertEquals("HTTP2", s.protocol());
        assertEquals("SETTINGS, HEADERS[1]", s.info());

        byte[] preface = concat("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(), new byte[] { 0, 0, 0, 4, 0, 0, 0, 0, 0 });
        PacketSummary p = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + preface.length), tcp(50000, 8080, 0x18), preface));
        assertEquals("HTTP2", p.protocol());
        assertEquals("Connection preface, SETTINGS", p.info());

        byte[] partial = { 0, 0x40, 0, 0, 0, 0, 0, 0, 1, 1, 2, 3 }; // a DATA frame of 16 KiB, cut by the segment
        PacketSummary t = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + partial.length), tcp(8080, 50000, 0x18), partial));
        assertEquals("TCP", t.protocol());
    }

    @Test
    void vlanTaggedIpv4Udp() {
        byte[] packet = concat(ethernet(0x8100), new byte[] { 0, 1, 0x08, 0x00 },
                ipv4(17, new byte[] { (byte) 192, (byte) 168, 1, 1 }, new byte[] { (byte) 192, (byte) 168, 1, 2 }, 12),
                udp(53, 5353, 12));
        PacketSummary s = PacketSummary.decode(LinkType.ETHERNET, packet);
        assertEquals("UDP", s.protocol());
        assertEquals("192.168.1.1:53", s.source());
        assertEquals("53 → 5353 Len=4", s.info());
    }

    @Test
    void bsdLoopbackIpv6Tcp() {
        byte[] loopbackHeader = { 30, 0, 0, 0 };
        byte[] src = new byte[16];
        src[15] = 1;
        byte[] packet = concat(loopbackHeader, ipv6(6, src, src, 20), tcp(5000, 443, 0x18));
        PacketSummary s = PacketSummary.decode(LinkType.NULL, packet);
        assertEquals("TCP", s.protocol());
        assertEquals("0:0:0:0:0:0:0:1:5000", s.source());
        assertEquals("5000 → 443 [ACK, PSH] Seq=7 Len=0", s.info());
    }

    @Test
    void arpRequest() {
        ByteArrayOutputStream arp = new ByteArrayOutputStream();
        arp.writeBytes(new byte[] { 0, 1, 8, 0, 6, 4, 0, 1 });
        arp.writeBytes(new byte[] { 1, 2, 3, 4, 5, 6 });
        arp.writeBytes(new byte[] { 10, 0, 0, 1 });
        arp.writeBytes(new byte[6]);
        arp.writeBytes(new byte[] { 10, 0, 0, 9 });
        PacketSummary s = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0806), arp.toByteArray()));
        assertEquals("ARP", s.protocol());
        assertEquals("Who has 10.0.0.9? Tell 10.0.0.1", s.info());
    }

    @Test
    void truncatedPacketDoesNotThrow() {
        PacketSummary s = PacketSummary.decode(LinkType.ETHERNET, new byte[] { 1, 2, 3 });
        assertEquals("Malformed", s.protocol());
    }

}
