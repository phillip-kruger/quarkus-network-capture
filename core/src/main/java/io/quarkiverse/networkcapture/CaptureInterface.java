package io.quarkiverse.networkcapture;

/**
 * A network interface that can be captured on, the equivalent of one {@code pcap_if_t} entry returned by
 * {@code pcap_findalldevs} in <a href="https://www.tcpdump.org/manpages/pcap.3pcap.html">pcap(3PCAP)</a>.
 * Obtained from {@link CaptureInterfaces}; code that describes an interface of its own builds one with
 * {@link #builder()}.
 */
public interface CaptureInterface {

    /**
     * The OS name, e.g. {@code eth0}, {@code lo}, {@code en0}.
     */
    String name();

    /**
     * The OS interface index, as returned by {@code if_nametoindex(3)}.
     */
    int index();

    /**
     * Whether this is the loopback interface.
     */
    boolean loopback();

    /**
     * Whether the interface is up.
     */
    boolean up();

    static Builder builder() {
        return new DefaultCaptureInterface.Builder();
    }

    /**
     * Builds a {@link CaptureInterface}. Only {@link #name} is required; the index defaults to 0, the interface to
     * being up and not loopback.
     */
    interface Builder {

        Builder name(String name);

        Builder index(int index);

        Builder loopback(boolean loopback);

        Builder up(boolean up);

        /**
         * @throws IllegalStateException when the name is missing
         */
        CaptureInterface build();
    }
}
