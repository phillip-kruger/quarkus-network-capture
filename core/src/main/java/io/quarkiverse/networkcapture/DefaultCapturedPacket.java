package io.quarkiverse.networkcapture;

import java.util.Objects;

// The implementation behind the interface; package private so that only the builder and this package create it.
record DefaultCapturedPacket(CaptureInterface networkInterface, LinkType linkType, Packet packet)
        implements CapturedPacket {

    public DefaultCapturedPacket {
        Objects.requireNonNull(networkInterface, "networkInterface");
        Objects.requireNonNull(linkType, "linkType");
        Objects.requireNonNull(packet, "packet");
    }

    static final class Builder implements CapturedPacket.Builder {
        private CaptureInterface networkInterface;
        private LinkType linkType;
        private Packet packet;

        @Override
        public Builder networkInterface(CaptureInterface networkInterface) {
            this.networkInterface = networkInterface;
            return this;
        }

        @Override
        public Builder linkType(LinkType linkType) {
            this.linkType = linkType;
            return this;
        }

        @Override
        public Builder packet(Packet packet) {
            this.packet = packet;
            return this;
        }

        @Override
        public CapturedPacket build() {
            if (networkInterface == null || linkType == null || packet == null) {
                throw new IllegalStateException("networkInterface, linkType and packet are all required");
            }
            return new DefaultCapturedPacket(networkInterface, linkType, packet);
        }
    }
}
