package io.quarkiverse.networkcapture.internal.decode;

/**
 * Links a request and its response. On an HTTP/1.1 connection responses are returned in the order of the requests
 * (<a href="https://www.rfc-editor.org/rfc/rfc9112#section-9.3">RFC 9112 section 9.3</a>), so a response is paired
 * with the oldest request on the same connection that has no response yet. Interim {@code 1xx} responses do not
 * complete a request.
 *
 * @param id identifies the exchange within one {@link HttpStreamDecoder}
 * @param request the request line, e.g. {@code GET /hello HTTP/1.1}
 * @param isRequest whether the packet carrying this is the request, as opposed to the response or a part of it
 */
public record HttpExchange(long id, String request, boolean isRequest) {
}
