package io.quarkiverse.networkcapture;

/**
 * Link layer header type of captured packets, using the {@code LINKTYPE_*} values of the
 * <a href="https://www.tcpdump.org/linktypes.html">tcpdump.org link-layer header types registry</a>, which pcap and pcapng files use to tell readers
 * how to dissect the first bytes of every packet.
 * <p>
 * References: {@code LinkType} field of the Interface Description Block in the <a href="https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/">PCAP Next Generation (pcapng) Capture File Format</a>;
 * <a href="https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html">LINKTYPE_NULL</a> for the BSD loopback encapsulation.
 */
public enum LinkType {
    /**
     * BSD loopback: a 4 byte host-endian protocol family header. Used by macOS {@code lo0}.
     */
    NULL(0),
    /**
     * Ethernet. Also, what Linux produces on {@code lo}.
     */
    ETHERNET(1),
    /**
     * Raw IP, no link layer header. Used by tun devices.
     */
    RAW(101);

    private final int pcapValue;

    LinkType(int pcapValue) {
        this.pcapValue = pcapValue;
    }

    public int pcapValue() {
        return pcapValue;
    }

    public static LinkType fromPcapValue(int value) {
        for (LinkType t : values()) {
            if (t.pcapValue == value) {
                return t;
            }
        }
        throw new CaptureException("Unsupported link type: " + value);
    }
}
