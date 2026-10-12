package io.quarkiverse.networkcapture.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import io.quarkiverse.networkcapture.LinkType;
import io.quarkiverse.networkcapture.TestPcapng;

import org.junit.jupiter.api.Test;

class PcapngWriterTest {


    @Test
    void writesWellFormedBlocks() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PcapngWriter writer = new PcapngWriter(out, "test");
        int lo = writer.addInterface("lo", LinkType.ETHERNET, 1000);
        int en = writer.addInterface("en0", LinkType.NULL, 65535);
        assertEquals(0, lo);
        assertEquals(1, en);
        byte[] odd = { 1, 2, 3, 4, 5 };
        byte[] aligned = { 9, 9, 9, 9 };
        writer.writePacket(lo, 1_700_000_000_123_456_789L, 5, odd);
        writer.writePacket(en, 1L << 40, 100, aligned);
        writer.close();

        var blocks = TestPcapng.parse(out.toByteArray());
        assertEquals(5, blocks.size());

        ByteBuffer shb = body(blocks.getFirst());
        assertEquals(0x0A0D0D0A, blocks.getFirst().type());
        assertEquals(0x1A2B3C4D, shb.getInt());
        assertEquals(1, shb.getShort());
        assertEquals(0, shb.getShort());
        assertEquals(-1L, shb.getLong());

        ByteBuffer idb = body(blocks.get(1));
        assertEquals(1, blocks.get(1).type());
        assertEquals(1, idb.getShort());
        idb.getShort();
        assertEquals(1000, idb.getInt());
        assertEquals(2, idb.getShort()); // if_name
        assertEquals(2, idb.getShort());
        assertEquals('l', idb.get());
        assertEquals('o', idb.get());
        idb.getShort(); // padding
        assertEquals(9, idb.getShort()); // if_tsresol
        assertEquals(1, idb.getShort());
        assertEquals(9, idb.get());

        assertEquals(0, body(blocks.get(2)).getShort());

        ByteBuffer epb = body(blocks.get(3));
        assertEquals(6, blocks.get(3).type());
        assertEquals(0, epb.getInt());
        long ts = ((long) epb.getInt() << 32) | Integer.toUnsignedLong(epb.getInt());
        assertEquals(1_700_000_000_123_456_789L, ts);
        assertEquals(5, epb.getInt());
        assertEquals(5, epb.getInt());
        byte[] data = new byte[5];
        epb.get(data);
        assertArrayEquals(odd, data);
        assertEquals(3, epb.remaining(), "payload padded to 32 bits");

        ByteBuffer epb2 = body(blocks.get(4));
        assertEquals(1, epb2.getInt());
        assertEquals(1L << 40, ((long) epb2.getInt() << 32) | Integer.toUnsignedLong(epb2.getInt()));
        assertEquals(4, epb2.getInt());
        assertEquals(100, epb2.getInt());
        assertEquals(4, epb2.remaining());
    }

    @Test
    void rejectsUnknownInterface() {
        PcapngWriter writer = new PcapngWriter(new ByteArrayOutputStream(), "test");
        assertThrows(IllegalArgumentException.class, () -> writer.writePacket(0, 0, 0, new byte[0]));
    }

    private static ByteBuffer body(TestPcapng.Block block) {
        return ByteBuffer.wrap(block.body()).order(ByteOrder.LITTLE_ENDIAN);
    }

}
