package io.quarkiverse.networkcapture;

import static io.quarkiverse.networkcapture.TestPackets.captured;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;


import org.junit.jupiter.api.Test;
import io.quarkiverse.networkcapture.internal.ProcessEndpoints;


class ApplicationTrafficFilterTest {


    @Test
    void acceptsOnlyPacketsOnKnownPorts() {
        ProcessEndpoints fixed = (tcp, udp) -> {
            tcp.add(8080);
            udp.add(5353);
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

}
