package io.quarkiverse.networkcapture;

import java.time.Instant;

// The implementation behind the interface; package private so that only the builder and this package create it.
record DefaultPacket(long timestampNanos, int originalLength, byte[] data) implements Packet {

    static final class Builder implements Packet.Builder {
        private Long timestampNanos;
        private Integer originalLength;
        private byte[] data;

        @Override
        public Builder timestampNanos(long timestampNanos) {
            this.timestampNanos = timestampNanos;
            return this;
        }

        @Override
        public Builder originalLength(int originalLength) {
            this.originalLength = originalLength;
            return this;
        }

        @Override
        public Builder data(byte[] data) {
            this.data = data;
            return this;
        }

        @Override
        public Packet build() {
            if (data == null) {
                throw new IllegalStateException("data is required");
            }
            long timestamp = timestampNanos != null ? timestampNanos : now();
            return new DefaultPacket(timestamp, originalLength != null ? originalLength : data.length, data);
        }

        private static long now() {
            Instant now = Instant.now();
            return now.getEpochSecond() * 1_000_000_000L + now.getNano();
        }
    }
}
