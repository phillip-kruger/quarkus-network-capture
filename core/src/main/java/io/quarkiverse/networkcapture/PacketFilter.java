package io.quarkiverse.networkcapture;

import java.time.Duration;

/**
 * Decides whether a captured packet is kept. Called on the session's writer thread, one packet at a time, so an
 * implementation needs no synchronisation of its own but must not block: nothing is written while it runs.
 */
@FunctionalInterface
public interface PacketFilter {

    boolean accept(CapturedPacket packet);

    /**
     * How long a {@link CaptureSession} holds a packet before asking this filter about it. A filter that learns from
     * the environment, such as {@link ApplicationTrafficFilter}, uses this to see state that appears shortly after the
     * packet. Zero by default.
     */
    default Duration hold() {
        return Duration.ZERO;
    }

    default PacketFilter and(PacketFilter other) {
        PacketFilter self = this;
        return new PacketFilter() {
            @Override
            public boolean accept(CapturedPacket packet) {
                return self.accept(packet) && other.accept(packet);
            }

            @Override
            public Duration hold() {
                return self.hold().compareTo(other.hold()) >= 0 ? self.hold() : other.hold();
            }
        };
    }
}
