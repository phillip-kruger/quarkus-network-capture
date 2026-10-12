package io.quarkiverse.networkcapture.internal.decode;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;

// Decides whether HTTP body bytes can be shown as text.
final class BodyText {

    private BodyText() {
    }

    /**
     * The bytes as text when they are valid UTF-8 without control characters other than whitespace, or null for
     * binary content. At most {@code limit} characters are returned.
     */
    static String of(byte[] body, int limit) {
        if (body.length == 0) {
            return "";
        }
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(body)).toString();
        } catch (CharacterCodingException e) {
            return null;
        }
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') {
                return null;
            }
        }
        return text.length() > limit ? text.substring(0, limit) : text;
    }
}
