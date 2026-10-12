package io.quarkiverse.networkcapture.internal.decode;

import java.net.InetAddress;
import java.net.UnknownHostException;
import io.quarkiverse.networkcapture.LinkType;

/**
 * The IPv4 or IPv6 header of a captured packet.
 * <p>
 * References: <a href="https://www.rfc-editor.org/rfc/rfc791">RFC 791</a> (IPv4 header, {@code IHL},
 * {@code Total Length} and {@code Protocol}); <a href="https://www.rfc-editor.org/rfc/rfc8200">RFC 8200</a> (IPv6
 * header, {@code Payload Length} and {@code Next Header}; extension headers are not followed).
 *
 * @param version 4 or 6
 * @param protocol the transport protocol number, e.g. {@link #TCP} or {@link #UDP}
 * @param source textual source address
 * @param destination textual destination address
 * @param payloadOffset index of the first byte after the IP header
 * @param payloadEnd index after the last byte of the IP payload that is present in the captured data
 */
record IpPacket(int version, int protocol, String source, String destination, int payloadOffset, int payloadEnd) {

    static final int ICMP = 1;
    static final int TCP = 6;
    static final int UDP = 17;
    static final int ICMPV6 = 58;

    // Returns the IP header, or null when the packet is not IPv4 or IPv6 or is truncated
    static IpPacket of(LinkType linkType, byte[] d) {
        NetworkLayer network = NetworkLayer.of(linkType, d);
        if (network == null) {
            return null;
        }
        return of(network, d);
    }

    static IpPacket of(NetworkLayer network, byte[] d) {
        int o = network.offset();
        try {
            if (network.etherType() == NetworkLayer.IPV4 && (d[o] & 0xF0) >> 4 == 4) {
                int ihl = (d[o] & 0x0F) * 4;
                int total = NetworkLayer.u16(d, o + 2);
                return new IpPacket(4, d[o + 9] & 0xFF, ipv4(d, o + 12), ipv4(d, o + 16), o + ihl, Math.min(o + total, d.length));
            }
            if (network.etherType() == NetworkLayer.IPV6 && (d[o] & 0xF0) >> 4 == 6) {
                int payloadLength = NetworkLayer.u16(d, o + 4);
                return new IpPacket(6, d[o + 6] & 0xFF, ipv6(d, o + 8), ipv6(d, o + 24), o + 40,
                        Math.min(o + 40 + payloadLength, d.length));
            }
            return null;
        } catch (IndexOutOfBoundsException e) {
            return null;
        }
    }

    static String ipv4(byte[] d, int o) {
        return (d[o] & 0xFF) + "." + (d[o + 1] & 0xFF) + "." + (d[o + 2] & 0xFF) + "." + (d[o + 3] & 0xFF);
    }

    private static String ipv6(byte[] d, int o) {
        byte[] addr = new byte[16];
        System.arraycopy(d, o, addr, 0, 16);
        try {
            return InetAddress.getByAddress(addr).getHostAddress();
        } catch (UnknownHostException e) {
            return "?";
        }
    }
}
