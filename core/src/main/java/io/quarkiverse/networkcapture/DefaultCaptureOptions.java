package io.quarkiverse.networkcapture;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

// The implementation behind the interface; package private so that only the builder and this package create it.
record DefaultCaptureOptions(int snapLen, boolean promiscuous, Optional<Elevation> elevation, Duration helperTimeout)
        implements CaptureOptions {

    static final class Builder implements CaptureOptions.Builder {
        private int snapLen = 262144;
        private boolean promiscuous;
        private Elevation elevation = Elevation.detect();
        private Duration helperTimeout = Duration.ofMinutes(2);

        @Override
        public Builder snapLen(int snapLen) {
            if (snapLen <= 0) {
                throw new IllegalArgumentException("snapLen must be positive");
            }
            this.snapLen = snapLen;
            return this;
        }

        @Override
        public Builder promiscuous(boolean promiscuous) {
            this.promiscuous = promiscuous;
            return this;
        }

        @Override
        public Builder elevation(Elevation elevation) {
            this.elevation = elevation;
            return this;
        }

        @Override
        public Builder helperTimeout(Duration helperTimeout) {
            this.helperTimeout = Objects.requireNonNull(helperTimeout, "helperTimeout");
            return this;
        }

        @Override
        public CaptureOptions build() {
            return new DefaultCaptureOptions(snapLen, promiscuous, Optional.ofNullable(elevation), helperTimeout);
        }
    }
}
