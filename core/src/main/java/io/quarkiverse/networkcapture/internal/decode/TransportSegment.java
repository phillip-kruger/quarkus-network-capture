package io.quarkiverse.networkcapture.internal.decode;

import io.quarkiverse.networkcapture.LinkType;


/**
 * The TCP or UDP header of a captured packet: ports, TCP flags, and where the payload is.
 * <p>
 * References: <a href="https://www.rfc-editor.org/rfc/rfc9293">RFC 9293</a> (TCP header, data offset and control
 * bits) and <a href="https://www.rfc-editor.org/rfc/rfc768">RFC 768</a> (UDP header), whose ports are the first four
 * bytes in both; see {@link IpPacket} for the network layer.
 *
 * @param tcp whether this is TCP, as opposed to UDP
 * @param sourcePort source port
 * @param destinationPort destination port
 * @param flags the TCP control bits, {@code FIN} being bit 0 and {@code RST} bit 2; 0 for UDP
 * @param sequence the TCP sequence number; 0 for UDP
 * @param payloadOffset index of the first payload byte in the captured data
 * @param payloadLength number of payload bytes present in the captured data
 */
public record TransportSegment(boolean tcp, int sourcePort, int destinationPort, int flags, long sequence, int payloadOffset,
        int payloadLength) {

    static final int FIN = 0x01;
    static final int SYN = 0x02;
    static final int RST = 0x04;
    static final int PSH = 0x08;
    static final int ACK = 0x10;

    public boolean closes() {
        return (flags & (FIN | RST)) != 0;
    }

    // Returns the segment, or null when the packet is not TCP or UDP over IPv4 or IPv6, or is truncated
    public static TransportSegment of(LinkType linkType, byte[] d) {
        IpPacket ip = IpPacket.of(linkType, d);
        return ip == null ? null : of(ip, d);
    }

    static TransportSegment of(IpPacket ip, byte[] d) {
        int o = ip.payloadOffset();
        try {
            int sourcePort = NetworkLayer.u16(d, o);
            int destinationPort = NetworkLayer.u16(d, o + 2);
            if (ip.protocol() == IpPacket.TCP) {
                int dataOffset = ((d[o + 12] & 0xF0) >> 4) * 4;
                int flags = d[o + 13] & 0xFF;
                long sequence = Integer.toUnsignedLong(NetworkLayer.u16(d, o + 4) << 16 | NetworkLayer.u16(d, o + 6));
                int payload = o + dataOffset;
                return new TransportSegment(true, sourcePort, destinationPort, flags, sequence, payload,
                        Math.max(0, Math.min(ip.payloadEnd(), d.length) - payload));
            }
            if (ip.protocol() == IpPacket.UDP) {
                int length = NetworkLayer.u16(d, o + 4);
                return new TransportSegment(false, sourcePort, destinationPort, 0, 0, o + 8,
                        Math.max(0, Math.min(o + length, d.length) - (o + 8)));
            }
            return null;
        } catch (IndexOutOfBoundsException e) {
            return null;
        }
    }
}
