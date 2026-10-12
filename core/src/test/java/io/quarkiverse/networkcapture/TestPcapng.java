package io.quarkiverse.networkcapture;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

// A minimal pcapng reader for assertions.
public final class TestPcapng {

    private TestPcapng() {
    }

    public record Block(int type, byte[] body) {
    }

    // Walks the blocks, checking both length fields and 32 bit alignment.
    public static List<Block> parse(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        List<Block> blocks = new ArrayList<>();
        while (buffer.hasRemaining()) {
            int type = buffer.getInt();
            int length = buffer.getInt();
            assertEquals(0, length % 4, "block length must be a multiple of 4");
            byte[] body = new byte[length - 12];
            buffer.get(body);
            assertEquals(length, buffer.getInt(), "trailing block length");
            blocks.add(new Block(type, body));
        }
        return blocks;
    }
}
