package io.quarkiverse.networkcapture.internal;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import io.quarkiverse.networkcapture.LinkType;

/**
 * Writes a pcapng file: one Section Header Block, one Interface Description Block per interface, then Enhanced
 * Packet Blocks, all little endian with nanosecond timestamps ({@code if_tsresol = 9}). Thread safe.
 * <p>
 * References: <a href="https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/">PCAP Next Generation (pcapng) Capture File Format</a> (block structure in section 3, Section Header Block in 4.1,
 * Interface Description Block in 4.2, Enhanced Packet Block in 4.3, option codes in each block's section);
 * <a href="https://wiki.wireshark.org/Development/PcapNg">Wireshark's pcapng development notes</a>.
 */
public final class PcapngWriter implements AutoCloseable {

    private static final int SECTION_HEADER_BLOCK = 0x0A0D0D0A;
    private static final int INTERFACE_DESCRIPTION_BLOCK = 1;
    private static final int ENHANCED_PACKET_BLOCK = 6;
    private static final int BYTE_ORDER_MAGIC = 0x1A2B3C4D;
    private static final short OPT_ENDOFOPT = 0;
    private static final short SHB_USERAPPL = 4;
    private static final short IF_NAME = 2;
    private static final short IF_TSRESOL = 9;

    private final OutputStream out;
    private int interfaces;
    private boolean closed;

    public PcapngWriter(OutputStream out, String application) {
        this.out = out instanceof BufferedOutputStream ? out : new BufferedOutputStream(out, 1 << 16);
        ByteBuffer body = buffer(16 + optionSize(application.length()) + 4);
        body.putInt(BYTE_ORDER_MAGIC).putShort((short) 1).putShort((short) 0).putLong(-1L);
        putStringOption(body, SHB_USERAPPL, application);
        putEndOfOptions(body);
        writeBlock(SECTION_HEADER_BLOCK, body);
    }

    public static PcapngWriter create(Path file, String application) {
        try {
            return new PcapngWriter(Files.newOutputStream(file), application);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Adds an interface description block.
     *
     * @return the interface id to use in {@link #writePacket}
     */
    public synchronized int addInterface(String name, LinkType linkType, int snapLen) {
        ByteBuffer body = buffer(8 + optionSize(name.length()) + optionSize(1) + 4);
        body.putShort((short) linkType.pcapValue()).putShort((short) 0).putInt(snapLen);
        putStringOption(body, IF_NAME, name);
        body.putShort(IF_TSRESOL).putShort((short) 1).put((byte) 9).put((byte) 0).put((byte) 0).put((byte) 0);
        putEndOfOptions(body);
        writeBlock(INTERFACE_DESCRIPTION_BLOCK, body);
        return interfaces++;
    }

    public synchronized void writePacket(int interfaceId, long timestampNanos, int originalLength, byte[] data) {
        if (interfaceId < 0 || interfaceId >= interfaces) {
            throw new IllegalArgumentException("Unknown interface id " + interfaceId);
        }
        ByteBuffer body = buffer(20 + pad4(data.length));
        body.putInt(interfaceId)
                .putInt((int) (timestampNanos >>> 32))
                .putInt((int) timestampNanos)
                .putInt(data.length)
                .putInt(originalLength)
                .put(data)
                .position(20 + pad4(data.length));
        writeBlock(ENHANCED_PACKET_BLOCK, body);
    }

    public synchronized void flush() {
        try {
            out.flush();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        try {
            out.close();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private void writeBlock(int type, ByteBuffer body) {
        int bodyLength = body.position();
        int totalLength = 12 + bodyLength;
        ByteBuffer block = buffer(totalLength);
        block.putInt(type).putInt(totalLength).put(body.array(), 0, bodyLength).putInt(totalLength);
        try {
            out.write(block.array(), 0, totalLength);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static ByteBuffer buffer(int capacity) {
        return ByteBuffer.allocate(capacity).order(ByteOrder.LITTLE_ENDIAN);
    }

    private static void putStringOption(ByteBuffer buffer, short code, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        buffer.putShort(code).putShort((short) bytes.length).put(bytes);
        for (int i = bytes.length; i < pad4(bytes.length); i++) {
            buffer.put((byte) 0);
        }
    }

    private static void putEndOfOptions(ByteBuffer buffer) {
        buffer.putShort(OPT_ENDOFOPT).putShort((short) 0);
    }

    private static int optionSize(int valueLength) {
        return 4 + pad4(valueLength);
    }

    private static int pad4(int n) {
        return (n + 3) & ~3;
    }
}
