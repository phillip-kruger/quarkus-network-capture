package io.quarkiverse.networkcapture.internal.decode;

import io.quarkiverse.networkcapture.LinkType;


/**
 * Where the network layer of a captured packet starts and which protocol it carries, after walking the link layer
 * header of the capture's {@link LinkType}, including IEEE 802.1Q VLAN tags.
 * <p>
 * References: the {@code LINKTYPE_*} entries of the
 * <a href="https://www.tcpdump.org/linktypes.html">tcpdump.org link-layer header types registry</a>, in particular
 * <a href="https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html">LINKTYPE_NULL</a>, whose 4 byte protocol family
 * is in host byte order; IEEE 802.1Q VLAN tags (<a href="https://wiki.wireshark.org/VLAN">Wireshark wiki</a>).
 *
 * @param etherType the network protocol as an EtherType, e.g. {@link #IPV4}, {@link #IPV6} or {@link #ARP}, or -1 when
 *        unknown
 * @param offset index of the first byte of the network layer header
 */
record NetworkLayer(int etherType, int offset) {

    static final int IPV4 = 0x0800;
    static final int ARP = 0x0806;
    static final int VLAN = 0x8100;
    static final int IPV6 = 0x86DD;

    // Returns the network layer, or null when the packet is too short to tell
    static NetworkLayer of(LinkType linkType, byte[] d) {
        try {
            return switch (linkType) {
                case ETHERNET -> {
                    int type = u16(d, 12);
                    int o = 14;
                    while (type == VLAN) {
                        type = u16(d, o + 2);
                        o += 4;
                    }
                    yield new NetworkLayer(type, o);
                }
                case NULL -> {
                    // 4 byte protocol family in host byte order; 2 is AF_INET, 24/28/30 are AF_INET6 variants
                    int family = d[0] & 0xFF | (d[3] & 0xFF) << 24;
                    yield new NetworkLayer(family == 2 ? IPV4 : family == 24 || family == 28 || family == 30 ? IPV6 : -1, 4);
                }
                case RAW -> {
                    int version = (d[0] & 0xF0) >> 4;
                    yield new NetworkLayer(version == 4 ? IPV4 : version == 6 ? IPV6 : -1, 0);
                }
            };
        } catch (IndexOutOfBoundsException e) {
            return null;
        }
    }

    static int u16(byte[] d, int o) {
        return (d[o] & 0xFF) << 8 | (d[o + 1] & 0xFF);
    }
}
