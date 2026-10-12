package io.quarkiverse.networkcapture;

import java.io.ByteArrayOutputStream;


// Builders for synthetic packets.
public final class TestPackets {

    private TestPackets() {
    }

    public static byte[] ethernet(int type) {
        byte[] h = new byte[14];
        h[12] = (byte) (type >> 8);
        h[13] = (byte) type;
        return h;
    }

    public static byte[] ipv4(int proto, byte[] src, byte[] dst, int payloadLength) {
        byte[] h = new byte[20];
        h[0] = 0x45;
        int total = 20 + payloadLength;
        h[2] = (byte) (total >> 8);
        h[3] = (byte) total;
        h[9] = (byte) proto;
        System.arraycopy(src, 0, h, 12, 4);
        System.arraycopy(dst, 0, h, 16, 4);
        return h;
    }

    public static byte[] ipv6(int nextHeader, byte[] src, byte[] dst, int payloadLength) {
        byte[] h = new byte[40];
        h[0] = 0x60;
        h[4] = (byte) (payloadLength >> 8);
        h[5] = (byte) payloadLength;
        h[6] = (byte) nextHeader;
        System.arraycopy(src, 0, h, 8, 16);
        System.arraycopy(dst, 0, h, 24, 16);
        return h;
    }

    public static byte[] tcp(int sport, int dport, int flags) {
        byte[] h = new byte[20];
        h[0] = (byte) (sport >> 8);
        h[1] = (byte) sport;
        h[2] = (byte) (dport >> 8);
        h[3] = (byte) dport;
        h[7] = 7; // sequence number
        h[12] = 0x50; // data offset 5 words
        h[13] = (byte) flags;
        return h;
    }

    public static byte[] udp(int sport, int dport, int length) {
        byte[] h = new byte[length];
        h[0] = (byte) (sport >> 8);
        h[1] = (byte) sport;
        h[2] = (byte) (dport >> 8);
        h[3] = (byte) dport;
        h[5] = (byte) length;
        return h;
    }

    public static byte[] loopbackTcp(int sport, int dport) {
        byte[] lo = { 127, 0, 0, 1 };
        return concat(ethernet(0x0800), ipv4(6, lo, lo, 20), tcp(sport, dport, 0x18));
    }

    // An Ethernet packet as a session would hand it to a filter, captured on the loopback interface.
    public static CapturedPacket captured(byte[] data) {
        return CapturedPacket.builder()
                .networkInterface(CaptureInterface.builder().name("lo").index(1).loopback(true).build())
                .linkType(LinkType.ETHERNET)
                .packet(Packet.builder().timestampNanos(0).data(data).build())
                .build();
    }

    public static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.writeBytes(p);
        }
        return out.toByteArray();
    }
}
