package io.quarkiverse.networkcapture.internal.decode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * An HTTP/1.x message as found at the start of one TCP segment: the start line, the header fields, and the part of
 * the body that is in the same segment. Nothing is reassembled across segments, so a body may be incomplete; compare
 * {@link #body()} with {@link #contentLength()}.
 * <p>
 * References: <a href="https://www.rfc-editor.org/rfc/rfc9112">RFC 9112</a> (HTTP/1.1 message format: request line,
 * status line, field lines, and the empty line that ends the header section; a payload is recognised as a message
 * when its first line is a request line or a status line);
 * <a href="https://www.rfc-editor.org/rfc/rfc9110">RFC 9110</a> (field semantics, {@code Host} and
 * {@code Content-Length}).
 *
 * @param method request method, or null for a response
 * @param target request target as sent, usually a path, or null for a response
 * @param version e.g. {@code HTTP/1.1}
 * @param status status code, or 0 for a request
 * @param reason reason phrase, or null for a request
 * @param headers header fields in order
 * @param body body bytes present in the segment, possibly empty
 * @param contentLength the {@code Content-Length} header value, or -1 when absent or invalid
 */
public record HttpMessage(String method, String target, String version, int status, String reason, List<Header> headers,
        byte[] body, long contentLength) {

    public record Header(String name, String value) {
    }

    private static final byte[] HEADER_END = { '\r', '\n', '\r', '\n' };
    private static final int MAX_START_LINE = 200;
    private static final Pattern REQUEST_LINE = Pattern.compile("[A-Z]{3,7} \\S+ HTTP/1\\.[01]");
    private static final Pattern STATUS_LINE = Pattern.compile("HTTP/1\\.[01] [1-5][0-9]{2}(?: .*)?");

    /**
     * Parses the message starting at {@code o}.
     *
     * @return the message, or null when the payload does not start with a request or status line, or the header
     *         section is not complete within the segment
     */
    static HttpMessage parse(byte[] d, int o, int len) {
        if (startLine(d, o, len) == null) {
            return null;
        }
        int end = indexOf(d, o, o + len, HEADER_END);
        if (end < 0) {
            return null;
        }
        String head = new String(d, o, end - o, StandardCharsets.ISO_8859_1);
        String[] lines = head.split("\r\n");
        String[] start = lines[0].split(" ", 3);
        List<Header> headers = new ArrayList<>();
        long contentLength = -1;
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon <= 0) {
                continue;
            }
            Header header = new Header(lines[i].substring(0, colon).trim(), lines[i].substring(colon + 1).trim());
            headers.add(header);
            if (header.name().equalsIgnoreCase("Content-Length")) {
                try {
                    contentLength = Long.parseLong(header.value());
                } catch (NumberFormatException ignored) {
                }
            }
        }
        byte[] body = Arrays.copyOfRange(d, end + HEADER_END.length, o + len);
        if (start[0].startsWith("HTTP/")) {
            int status = start.length > 1 ? Integer.parseInt(start[1]) : 0;
            return new HttpMessage(null, null, start[0], status, start.length > 2 ? start[2] : "", headers, body, contentLength);
        }
        return new HttpMessage(start[0], start.length > 1 ? start[1] : "", start.length > 2 ? start[2] : "", 0, null, headers,
                body, contentLength);
    }

    /**
     * The request line or status line a payload starts with, or null when it does not start with one. Unlike
     * {@link #parse} this does not need the header section to be complete.
     */
    static String startLine(byte[] d, int o, int len) {
        if (len < 12) {
            return null;
        }
        int end = -1;
        for (int i = o; i < o + Math.min(len, MAX_START_LINE) - 1; i++) {
            byte b = d[i];
            if (b == '\r' && d[i + 1] == '\n') {
                end = i;
                break;
            }
            if (b < 0x20 || b > 0x7E) {
                return null;
            }
        }
        if (end < 0) {
            return null;
        }
        String line = new String(d, o, end - o, StandardCharsets.US_ASCII);
        return REQUEST_LINE.matcher(line).matches() || STATUS_LINE.matcher(line).matches() ? line : null;
    }

    public boolean isRequest() {
        return method != null;
    }

    // The request line or status line, e.g. GET /hello HTTP/1.1 or HTTP/1.1 200 OK.
    public String startLine() {
        return isRequest() ? method + " " + target + " " + version : version + " " + status + " " + reason;
    }

    // The first header with this name, ignoring case, or null.
    public String header(String name) {
        for (Header h : headers) {
            if (h.name().equalsIgnoreCase(name)) {
                return h.value();
            }
        }
        return null;
    }

    /**
     * The request URL, built from the {@code Host} header and the target, or just the target when it is already
     * absolute. Null for responses. The scheme is {@code http} because this is a cleartext capture.
     */
    public String url() {
        if (!isRequest()) {
            return null;
        }
        if (target.contains("://") || target.equals("*")) {
            return target;
        }
        String host = header("Host");
        return host == null ? target : "http://" + host + target;
    }

    // Whether every byte announced by Content-Length is in body(); true when the length is unknown.
    public boolean bodyComplete() {
        return contentLength < 0 || body.length >= contentLength;
    }

    /**
     * The body as text when it is valid UTF-8 without control characters other than whitespace, or null for binary
     * content. At most {@code limit} characters are returned.
     */
    public String bodyAsText(int limit) {
        return BodyText.of(body, limit);
    }

    private static int indexOf(byte[] d, int from, int to, byte[] needle) {
        outer: for (int i = from; i <= to - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (d[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
