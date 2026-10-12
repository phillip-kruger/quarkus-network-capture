package io.quarkiverse.networkcapture;

import java.time.Duration;
import java.util.function.Consumer;

/**
 * An open capture on one interface, the counterpart of a {@code pcap_t} in libpcap. Obtain one through
 * {@link Capture}.
 * <p>
 * A handle may be created on one thread and polled on another, but {@link #poll} must not be called concurrently,
 * and a handle given to a {@link CaptureSession} belongs to the session, which polls and closes it.
 * <p>
 * References: <a href="https://www.tcpdump.org/manpages/pcap.3pcap.html">pcap(3PCAP)</a>, in particular {@code pcap_create}, {@code pcap_set_snaplen}
 * and {@code pcap_dispatch}, which this interface mirrors in spirit.
 */
public interface CaptureHandle extends AutoCloseable {

    CaptureInterface networkInterface();

    LinkType linkType();

    int snapLen();

    /**
     * Waits up to {@code timeout} for packets and delivers all that are immediately available.
     *
     * @return the number of packets delivered, 0 on timeout
     */
    int poll(Duration timeout, Consumer<Packet> sink);

    @Override
    void close();
}
