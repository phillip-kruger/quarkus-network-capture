package io.quarkiverse.networkcapture;

import java.time.Duration;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import io.smallrye.common.os.OS;
import io.smallrye.common.os.Process;
import io.quarkiverse.networkcapture.internal.LsofEndpoints;
import io.quarkiverse.networkcapture.internal.ProcSelfEndpoints;
import io.quarkiverse.networkcapture.internal.ProcessEndpoints;
import io.quarkiverse.networkcapture.internal.decode.TransportSegment;

/**
 * Keeps only TCP and UDP packets whose source or destination port belongs to a socket of this process.
 * <p>
 * The process's sockets are rescanned a few times per second, from the thread that calls {@link #accept}, which in a
 * session is the writer thread; the filter itself starts no thread. Because a
 * connection can open and close between two scans, the filter asks the session to hold packets for a second, so
 * that the decision for a packet is taken after later scans, and ports stay known for a grace period after their
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
    private final Map<Integer, Long> tcp = new ConcurrentHashMap<>();
    private final Map<Integer, Long> udp = new ConcurrentHashMap<>();
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
        Map<Integer, Long> known = segment.tcp() ? tcp : udp;
        return known.containsKey(segment.sourcePort()) || known.containsKey(segment.destinationPort());
    }

    void scan() {
        Set<Integer> tcpNow = new HashSet<>();
        Set<Integer> udpNow = new HashSet<>();
        endpoints.scan(tcpNow, udpNow);
        long now = System.nanoTime();
        for (Integer port : tcpNow) {
            tcp.put(port, now);
        }
        for (Integer port : udpNow) {
            udp.put(port, now);
        }
        tcp.values().removeIf(seen -> now - seen > GRACE_NANOS);
        udp.values().removeIf(seen -> now - seen > GRACE_NANOS);
        lastScanNanos = now;
    }
}
