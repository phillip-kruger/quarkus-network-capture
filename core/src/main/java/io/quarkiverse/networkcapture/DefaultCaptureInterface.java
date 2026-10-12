package io.quarkiverse.networkcapture;

// The implementation behind the interface; package private so that only the builder and this package create it.
record DefaultCaptureInterface(String name, int index, boolean loopback, boolean up) implements CaptureInterface {

    static final class Builder implements CaptureInterface.Builder {
        private String name;
        private int index;
        private boolean loopback;
        private boolean up = true;

        @Override
        public Builder name(String name) {
            this.name = name;
            return this;
        }

        @Override
        public Builder index(int index) {
            this.index = index;
            return this;
        }

        @Override
        public Builder loopback(boolean loopback) {
            this.loopback = loopback;
            return this;
        }

        @Override
        public Builder up(boolean up) {
            this.up = up;
            return this;
        }

        @Override
        public CaptureInterface build() {
            if (name == null) {
                throw new IllegalStateException("name is required");
            }
            return new DefaultCaptureInterface(name, index, loopback, up);
        }
    }
}
