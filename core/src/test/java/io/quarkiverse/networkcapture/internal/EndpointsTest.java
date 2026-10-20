package io.quarkiverse.networkcapture.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import io.smallrye.common.os.Process;

class EndpointsTest {

    @Test
    @EnabledOnOs(OS.LINUX)
    void procfsFindsOwnListeningSocket() throws Exception {
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Set<Endpoint> tcp = new HashSet<>();
            Set<Endpoint> udp = new HashSet<>();
            new ProcSelfEndpoints().scan(tcp, udp);
            Endpoint expected = new Endpoint(Endpoint.canonical(server.getInetAddress()), server.getLocalPort());
            assertTrue(tcp.contains(expected), expected + " not in " + tcp);
        }
    }

    @Test
    @EnabledIf("lsofAvailable")
    void lsofFindsOwnListeningSocket() throws Exception {
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Set<Endpoint> tcp = new HashSet<>();
            Set<Endpoint> udp = new HashSet<>();
            new LsofEndpoints(ProcessHandle.current().pid()).scan(tcp, udp);
            Endpoint expected = new Endpoint(Endpoint.canonical(server.getInetAddress()), server.getLocalPort());
            assertTrue(tcp.contains(expected), expected + " not in " + tcp);
        }
    }

    @Test
    void parsesLsofFieldOutput() {
        String output = """
                p1234
                f5
                PTCP
                n*:8080
                f6
                PTCP
                n127.0.0.1:5432->127.0.0.1:50000
                f7
                PUDP
                n[::1]:5353
                f8
                PTCP
                n[fe80::1]:9443->[fe80::2]:1234
                """;
        Set<Endpoint> tcp = new HashSet<>();
        Set<Endpoint> udp = new HashSet<>();
        LsofEndpoints.parse(output, tcp, udp);
        // only the local side of a connection, and a wildcard bind keeps a null address
        assertEquals(Set.of(new Endpoint(8080), new Endpoint("127.0.0.1", 5432),
                new Endpoint("fe80:0:0:0:0:0:0:1", 9443)), tcp);
        assertEquals(Set.of(new Endpoint("0:0:0:0:0:0:0:1", 5353)), udp);
    }

    @Test
    void decodesProcNetAddresses() {
        // the 32 bit words of /proc/net/tcp are in the host's byte order, little-endian here
        assertEquals("127.0.0.1", ProcSelfEndpoints.address("0100007F"));
        assertEquals("192.168.1.10", ProcSelfEndpoints.address("0A01A8C0"));
        assertNull(ProcSelfEndpoints.address("00000000"), "a wildcard bind has no address");
        assertEquals("0:0:0:0:0:0:0:1", ProcSelfEndpoints.address("00000000000000000000000001000000"));
        assertNull(ProcSelfEndpoints.address("00000000000000000000000000000000"), "nor an IPv6 wildcard bind");
        assertNull(ProcSelfEndpoints.address("nonsense"));
    }

    static boolean lsofAvailable() {
        for (String dir : System.getenv().getOrDefault("PATH", "").split(":")) {
            if (Files.isExecutable(Path.of(dir, "lsof"))) {
                return true;
            }
        }
        return false;
    }

}
