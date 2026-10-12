package io.quarkiverse.networkcapture;

/**
 * A packet as a {@link CaptureSession} hands it to filters and listeners: the packet itself and where it came from.
 * This is a single parameter object so that more context can be added later without changing
 * {@link PacketFilter} or {@link PacketListener}. Code that drives a filter or listener itself builds one with
 * {@link #builder()}.
 */
public interface CapturedPacket {

    /**
     * The interface the packet was captured on.
     */
    CaptureInterface networkInterface();

    /**
     * The link layer header type of {@link #packet()}'s data.
     */
    LinkType linkType();

    Packet packet();

    static Builder builder() {
        return new DefaultCapturedPacket.Builder();
    }

    /**
     * Builds a {@link CapturedPacket}; all three parts are required.
     */
    interface Builder {

        Builder networkInterface(CaptureInterface networkInterface);

        Builder linkType(LinkType linkType);

        Builder packet(Packet packet);

        /**
         * @throws IllegalStateException when a part is missing
         */
        CapturedPacket build();
    }
}
