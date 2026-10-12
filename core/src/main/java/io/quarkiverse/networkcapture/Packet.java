package io.quarkiverse.networkcapture;

/**
 * One captured packet, as a pcapng Enhanced Packet Block carries it: a timestamp, the length on the wire and the
 * captured bytes, which may be fewer than the wire length when truncated to the snap length. Code that feeds packets
 * from a source of its own builds them with {@link #builder()}.
 * <p>
 * References: section "Enhanced Packet Block" of the
 * <a href="https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/">PCAP Next Generation (pcapng) Capture File
 * Format</a>; the equivalent {@code struct pcap_pkthdr} in
 * <a href="https://www.tcpdump.org/manpages/pcap.3pcap.html">pcap(3PCAP)</a>.
 */
public interface Packet {

    /**
     * Capture time as nanoseconds since the Unix epoch.
     */
    long timestampNanos();

    /**
     * Length of the packet on the wire, which may exceed the length of {@link #data()} when truncated.
     */
    int originalLength();

    /**
     * The captured bytes, starting with the link layer header.
     */
    byte[] data();

    static Builder builder() {
        return new DefaultPacket.Builder();
    }

    /**
     * Builds a {@link Packet}. Only {@link #data} is required: the original length defaults to the data's length and
     * the timestamp to the current time.
     */
    interface Builder {

        Builder timestampNanos(long timestampNanos);

        Builder originalLength(int originalLength);

        Builder data(byte[] data);

        /**
         * @throws IllegalStateException when the data is missing
         */
        Packet build();
    }
}
