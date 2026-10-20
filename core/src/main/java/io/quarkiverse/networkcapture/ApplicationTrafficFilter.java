package io.quarkiverse.networkcapture;

import java.time.Duration;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import io.smallrye.common.os.OS;
import io.smallrye.common.os.Process;
import io.quarkiverse.networkcapture.internal.Endpoint;
import io.quarkiverse.networkcapture.internal.LsofEndpoints;
import io.quarkiverse.networkcapture.internal.ProcSelfEndpoints;
import io.quarkiverse.networkcapture.internal.ProcessEndpoints;
import io.quarkiverse.networkcapture.internal.decode.TransportSegment;

/**
 * Keeps only TCP and UDP packets one of whose endpoints, address and port together, is a socket of this process.
 * <p>
 * Matching the port alone would be enough for a server on a fixed port, but not for the ephemeral ports a process
 * also holds: another host's connection whose port happens to equal one of ours would be kept. So the address is
 * matched too, against the one the socket is bound to, a socket bound to a wildcard address matching the packet
 * whatever address it carries.
 * <p>
 * The process's sockets are rescanned a few times per second, from the thread that calls {@link #accept}, which in a
 * session is the writer thread; the filter itself starts no thread. Because a
 * connection can open and close between two scans, the filter asks the session to hold packets for a second, so
 * that the decision for a packet is taken after later scans, and endpoints stay known for a grace period after their
 * socket disappears so that the closing exchange is kept. Very short lived sockets, such as a UDP DNS lookup, can
 * still be missed.
 * <p>
 * References: {@link ProcSelfEndpoints} (Linux) and {@link LsofEndpoints} (macOS) for how the sockets are found.
 */
public final class ApplicationTrafficFilter implements PacketFilter {

    private static final Duration HOLD = Duration.ofSeconds(1);
    private static final long SCAN_INTERVAL_NANOS = Duration.ofMillis(250).toNanos();
    private static final long GRACE_NANOS = Duration.ofSeconds(10).toNanos();

    private final ProcessEndpoints endpoints;
    private final Map<Endpoint, Long> tcp = new ConcurrentHashMap<>();
    private final Map<Endpoint, Long> udp = new ConcurrentHashMap<>();
    private long lastScanNanos;
    private volatile String error;

    public static ApplicationTrafficFilter forCurrentProcess() {
        ProcessEndpoints endpoints = OS.LINUX.isCurrent()
                ? new ProcSelfEndpoints()
                : new LsofEndpoints(ProcessHandle.current().pid());
        return new ApplicationTrafficFilter(endpoints);
    }

    ApplicationTrafficFilter(ProcessEndpoints endpoints) {
        this.endpoints = endpoints;
        scan();
    }

    /**
     * The error that stopped the scanner, or null.
     */
    public String error() {
        return error;
    }

    @Override
    public Duration hold() {
        return HOLD;
    }

    @Override
    public boolean accept(CapturedPacket packet) {
        if (error == null && System.nanoTime() - lastScanNanos > SCAN_INTERVAL_NANOS) {
            try {
                scan();
            } catch (RuntimeException e) {
                error = e.getMessage();
            }
        }
        TransportSegment segment = TransportSegment.of(packet.linkType(), packet.packet().data());
        if (segment == null) {
            return false;
        }
        Map<Endpoint, Long> known = segment.tcp() ? tcp : udp;
        return matches(known, segment.source(), segment.sourcePort())
                || matches(known, segment.destination(), segment.destinationPort());
    }

    // Whether one of this process's sockets is bound to this address and port, or to this port on any address.
    private static boolean matches(Map<Endpoint, Long> known, String address, int port) {
        return known.containsKey(new Endpoint(address, port)) || known.containsKey(new Endpoint(port));
    }

    void scan() {
        Set<Endpoint> tcpNow = new HashSet<>();
        Set<Endpoint> udpNow = new HashSet<>();
        endpoints.scan(tcpNow, udpNow);
        long now = System.nanoTime();
        for (Endpoint endpoint : tcpNow) {
            tcp.put(endpoint, now);
        }
        for (Endpoint endpoint : udpNow) {
            udp.put(endpoint, now);
        }
        tcp.values().removeIf(seen -> now - seen > GRACE_NANOS);
        udp.values().removeIf(seen -> now - seen > GRACE_NANOS);
        lastScanNanos = now;
    }
}
