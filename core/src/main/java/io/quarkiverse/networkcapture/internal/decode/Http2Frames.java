package io.quarkiverse.networkcapture.internal.decode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Recognises HTTP/2 traffic in a TCP payload: the connection preface and whole frames. Header contents are HPACK
 * compressed and are not decoded.
 * <p>
 * References: <a href="https://www.rfc-editor.org/rfc/rfc9113">RFC 9113</a>, section 3.4 (connection preface) and
 * section 4.1 (frame format: 24 bit length, 8 bit type, 8 bit flags, 31 bit stream identifier).
 */
final class Http2Frames {

    private Http2Frames() {
    }

    private static final byte[] PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
    private static final String[] FRAME_TYPES = { "DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS",
            "PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION" };

    /**
     * The frames in {@code d[o, o+len)}, e.g. {@code SETTINGS, HEADERS[1]}, or null. Only a payload made of whole
     * frames is recognised: the frame lengths must chain exactly to the end of the segment, which rules out other
     * binary protocols and partial frames.
     */
    static String describe(byte[] d, int o, int len) {
        if (len >= PREFACE.length && Arrays.equals(d, o, o + PREFACE.length, PREFACE, 0, PREFACE.length)) {
            String rest = describe(d, o + PREFACE.length, len - PREFACE.length);
            return "Connection preface" + (rest == null ? "" : ", " + rest);
        }
        if (len < 9) {
            return null;
        }
        List<String> frames = new ArrayList<>();
        int p = o;
        int end = o + len;
        while (p < end) {
            if (end - p < 9) {
                return null;
            }
            int frameLength = (d[p] & 0xFF) << 16 | (d[p + 1] & 0xFF) << 8 | (d[p + 2] & 0xFF);
            int type = d[p + 3] & 0xFF;
            int stream = (NetworkLayer.u16(d, p + 5) << 16 | NetworkLayer.u16(d, p + 7)) & 0x7FFFFFFF;
            if (type >= FRAME_TYPES.length || p + 9 + frameLength > end) {
                return null;
            }
            frames.add(FRAME_TYPES[type] + (stream == 0 ? "" : "[" + stream + "]"));
            p += 9 + frameLength;
        }
        return String.join(", ", frames);
    }
}
