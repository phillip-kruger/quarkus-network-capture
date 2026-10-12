package io.quarkiverse.networkcapture.internal.decode;

/**
 * A piece of an HTTP/1.x message body that arrived in a TCP segment after the segment carrying the headers: the
 * decoded content of chunks for a {@code Transfer-Encoding: chunked} body, or the next bytes of a body sized by
 * {@code Content-Length}.
 * <p>
 * References: <a href="https://www.rfc-editor.org/rfc/rfc9112#section-7.1">RFC 9112 section 7.1</a> (chunked
 * transfer coding) and <a href="https://www.rfc-editor.org/rfc/rfc9112#section-6">section 6</a> (message body
 * length).
 *
 * @param message the start line of the message this body belongs to, e.g. {@code HTTP/1.1 404 Not Found}
 * @param data the decoded body bytes in this segment, chunk framing removed
 * @param chunked whether the body uses the chunked transfer coding
 * @param offset index of the first byte of {@code data} within the whole decoded body
 * @param total the whole body's size for a {@code Content-Length} body, or -1 when unknown
 * @param last whether this segment completes the body
 */
public record HttpBodyPart(String message, byte[] data, boolean chunked, long offset, long total, boolean last) {

    // Bytes still to come for a Content-Length body, or -1 when unknown.
    public long remaining() {
        return total < 0 ? -1 : total - offset - data.length;
    }

    // Same rules as HttpMessage#bodyAsText(int).
    public String asText(int limit) {
        return BodyText.of(data, limit);
    }
}
