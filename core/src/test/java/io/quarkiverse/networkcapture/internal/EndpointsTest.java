package io.quarkiverse.networkcapture.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
            Set<Integer> tcp = new HashSet<>();
            Set<Integer> udp = new HashSet<>();
            new ProcSelfEndpoints().scan(tcp, udp);
            assertTrue(tcp.contains(server.getLocalPort()), "port " + server.getLocalPort() + " not in " + tcp);
        }
    }

    @Test
    @EnabledIf("lsofAvailable")
    void lsofFindsOwnListeningSocket() throws Exception {
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Set<Integer> tcp = new HashSet<>();
            Set<Integer> udp = new HashSet<>();
            new LsofEndpoints(ProcessHandle.current().pid()).scan(tcp, udp);
            assertTrue(tcp.contains(server.getLocalPort()), "port " + server.getLocalPort() + " not in " + tcp);
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
        Set<Integer> tcp = new HashSet<>();
        Set<Integer> udp = new HashSet<>();
        LsofEndpoints.parse(output, tcp, udp);
        assertEquals(Set.of(8080, 5432, 9443), tcp);
        assertEquals(Set.of(5353), udp);
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
