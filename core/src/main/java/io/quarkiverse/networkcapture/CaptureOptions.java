package io.quarkiverse.networkcapture;

import java.time.Duration;
import java.util.Optional;

/**
 * How a capture is opened: what the handles record, and how the privilege to open them is obtained when the process
 * lacks it. Built with {@link #builder()}; {@link #DEFAULT} has every default.
 */
public interface CaptureOptions {

    CaptureOptions DEFAULT = builder().build();

    /**
     * Maximum number of bytes captured per packet, mirroring {@code pcap_set_snaplen} in
     * <a href="https://www.tcpdump.org/manpages/pcap.3pcap.html">pcap(3PCAP)</a>. The default matches libpcap's
     * {@code MAXIMUM_SNAPLEN}.
     */
    int snapLen();

    /**
     * Whether to put the interfaces into promiscuous mode, mirroring {@code pcap_set_promisc}. Off by default.
     */
    boolean promiscuous();

    /**
     * How the helper process acquires the privilege when the direct open is refused. {@link Elevation#detect()} by
     * default; when empty, a refused open fails with a {@link CapturePermissionException} instead of prompting.
     */
    Optional<Elevation> elevation();

    /**
     * How long to wait for the helper process, which includes the time the user takes to enter a password. Two
     * minutes by default.
     */
    Duration helperTimeout();

    static Builder builder() {
        return new DefaultCaptureOptions.Builder();
    }

    /**
     * Builds {@link CaptureOptions}; every setting has a default.
     */
    interface Builder {

        Builder snapLen(int snapLen);

        Builder promiscuous(boolean promiscuous);

        /**
         * @param elevation the mechanism, or null to never run the helper
         */
        Builder elevation(Elevation elevation);

        Builder helperTimeout(Duration helperTimeout);

        CaptureOptions build();
    }
}
