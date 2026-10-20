package io.quarkiverse.networkcapture.internal.decode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Recognises TLS in a TCP payload: the record headers, which are never encrypted, and the server name and ALPN
 * protocols of a Client Hello, the one message that is always in the clear. Nothing after the handshake can be
 * seen; such segments are reported as application data.
 * <p>
 * References: <a href="https://www.rfc-editor.org/rfc/rfc8446">RFC 8446</a>, section 5.1 (record layer: content
 * type, legacy version, length) and section 4.1.2 (Client Hello); <a href="https://www.rfc-editor.org/rfc/rfc6066">RFC
 * 6066</a>, section 3 (Server Name Indication); <a href="https://www.rfc-editor.org/rfc/rfc7301">RFC 7301</a>
 * (Application-Layer Protocol Negotiation).
 */
final class TlsRecords {

    private TlsRecords() {
    }

    private static final int CHANGE_CIPHER_SPEC = 0x14;
    private static final int ALERT = 0x15;
    private static final int HANDSHAKE = 0x16;
    private static final int APPLICATION_DATA = 0x17;
    private static final int CLIENT_HELLO = 1;
    private static final int SERVER_NAME = 0;
    private static final int ALPN = 16;

    /**
     * What is known about a TLS connection, from its Client Hello.
     *
     * @param serverName the Server Name Indication, or null
     * @param protocols the ALPN protocols offered, empty when the extension is absent
     */
    record Hello(String serverName, List<String> protocols) {

        // Whether the client said it will speak HTTP; false when it said nothing
        boolean http() {
            return protocols.contains("h2") || protocols.contains("http/1.1");
        }
    }

    /**
     * The records in {@code d[o, o+len)}, e.g. {@code Server Hello, Change Cipher Spec, Application Data}, or null when
     * the payload does not start with a record header; the last record may be cut by the segment. The hello, when
     * non-null, is the parsed Client Hello that the payload starts with.
     */
    record Summary(String info, Hello hello) {
    }

    static Summary describe(byte[] d, int o, int len) {
        int end = o + len;
        List<String> records = new ArrayList<>();
        Hello hello = null;
        int p = o;
        while (end - p >= 5) {
            int type = d[p] & 0xFF;
            if (type < CHANGE_CIPHER_SPEC || type > APPLICATION_DATA || d[p + 1] != 3 || d[p + 2] < 0 || d[p + 2] > 4) {
                return null;
            }
            int length = NetworkLayer.u16(d, p + 3);
            int body = p + 5;
            String name = switch (type) {
                case CHANGE_CIPHER_SPEC -> "Change Cipher Spec";
                case ALERT -> "Alert";
                case APPLICATION_DATA -> "Application Data";
                default -> handshake(d, body, Math.min(body + length, end));
            };
            if (records.isEmpty() && type == HANDSHAKE && body < end && d[body] == CLIENT_HELLO) {
                hello = clientHello(d, body + 4, Math.min(body + length, end));
            }
            records.add(name);
            p = body + length;
        }
        return records.isEmpty() ? null : new Summary(String.join(", ", records), hello);
    }

    private static String handshake(byte[] d, int o, int end) {
        if (o >= end) {
            return "Handshake";
        }
        return switch (d[o] & 0xFF) {
            case CLIENT_HELLO -> "Client Hello";
            case 2 -> "Server Hello";
            case 4 -> "New Session Ticket";
            case 11 -> "Certificate";
            case 12 -> "Server Key Exchange";
            case 14 -> "Server Hello Done";
            case 16 -> "Client Key Exchange";
            default -> "Handshake";
        };
    }

    // Parses the Client Hello body in d[o, end); the fields are read in order up to the extensions, and what is
    // missing from a truncated hello is left unset.
    private static Hello clientHello(byte[] d, int o, int end) {
        String serverName = null;
        List<String> protocols = new ArrayList<>();
        try {
            int p = o + 2 + 32; // version, random
            p += 1 + (d[p] & 0xFF); // session id
            p += 2 + NetworkLayer.u16(d, p); // cipher suites
            p += 1 + (d[p] & 0xFF); // compression methods
            int extensionsEnd = Math.min(p + 2 + NetworkLayer.u16(d, p), end);
            p += 2;
            while (p + 4 <= extensionsEnd) {
                int type = NetworkLayer.u16(d, p);
                int length = NetworkLayer.u16(d, p + 2);
                int data = p + 4;
                if (data + length > extensionsEnd) {
                    break;
                }
                if (type == SERVER_NAME && length >= 5 && d[data + 2] == 0) {
                    int nameLength = NetworkLayer.u16(d, data + 3);
                    serverName = new String(d, data + 5, Math.min(nameLength, length - 5), StandardCharsets.US_ASCII);
                } else if (type == ALPN && length >= 2) {
                    int q = data + 2;
                    while (q < data + length) {
                        int nameLength = d[q] & 0xFF;
                        protocols.add(new String(d, q + 1, Math.min(nameLength, data + length - q - 1), StandardCharsets.US_ASCII));
                        q += 1 + nameLength;
                    }
                }
                p = data + length;
            }
        } catch (IndexOutOfBoundsException e) {
            // truncated hello, keep what was read
        }
        return new Hello(serverName, protocols);
    }
}
