package io.quarkiverse.networkcapture;

import static io.quarkiverse.networkcapture.TestPackets.captured;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;


import org.junit.jupiter.api.Test;
import io.quarkiverse.networkcapture.internal.Endpoint;
import io.quarkiverse.networkcapture.internal.ProcessEndpoints;


class ApplicationTrafficFilterTest {


    @Test
    void acceptsOnlyPacketsOnKnownPorts() {
        // bound to a wildcard address, as a server is, so that any local address matches
        ProcessEndpoints fixed = (tcp, udp) -> {
            tcp.add(new Endpoint(8080));
            udp.add(new Endpoint(5353));
        };
        ApplicationTrafficFilter filter = new ApplicationTrafficFilter(fixed);
        {
            assertTrue(filter.accept(captured(TestPackets.loopbackTcp(40000, 8080))));
            assertTrue(filter.accept(captured(TestPackets.loopbackTcp(8080, 40000))));
            assertFalse(filter.accept(captured(TestPackets.loopbackTcp(40000, 9090))));
            assertFalse(filter.accept(captured(TestPackets.loopbackTcp(40000, 5353))),
                    "a UDP port must not match TCP traffic");
            byte[] lo = { 127, 0, 0, 1 };
            assertTrue(filter.accept(captured(TestPackets.concat(TestPackets.ethernet(0x0800),
                    TestPackets.ipv4(17, lo, lo, 12), TestPackets.udp(5353, 1234, 12)))));
            assertFalse(filter.accept(captured(TestPackets.ethernet(0x0806))), "ARP is dropped");
        }
    }

    @Test
    void rejectsForeignTrafficThatOnlySharesAPortNumber() {
        // The process holds one ephemeral socket, bound to 192.168.1.10:49502.
        byte[] self = { (byte) 192, (byte) 168, 1, 10 };
        byte[] peer = { (byte) 203, 0, 113, 5 };
        byte[] other = { (byte) 198, 51, 100, 7 };
        ProcessEndpoints fixed = (tcp, udp) -> tcp.add(new Endpoint("192.168.1.10", 49502));
        ApplicationTrafficFilter filter = new ApplicationTrafficFilter(fixed);
        assertTrue(filter.accept(captured(tcpBetween(self, peer, 49502, 443))), "the socket's own traffic is kept");
        assertTrue(filter.accept(captured(tcpBetween(peer, self, 443, 49502))), "in either direction");
        // Between two hosts that are not this machine, so neither endpoint can be a socket of this process.
        assertFalse(filter.accept(captured(tcpBetween(peer, other, 49502, 443))),
                "a packet between two foreign addresses must not be kept because a port number collides");
        assertFalse(filter.accept(captured(tcpBetween(peer, other, 443, 49502))),
                "nor when the colliding port is the destination");
    }

    private static byte[] tcpBetween(byte[] source, byte[] destination, int sourcePort, int destinationPort) {
        return TestPackets.concat(TestPackets.ethernet(0x0800), TestPackets.ipv4(6, source, destination, 20),
                TestPackets.tcp(sourcePort, destinationPort, 0x18));
    }

}
