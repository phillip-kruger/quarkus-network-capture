package io.quarkiverse.networkcapture.internal.decode;

import java.util.function.Predicate;
import io.quarkiverse.networkcapture.CapturedPacket;
import io.quarkiverse.networkcapture.PacketFilter;

/**
 * Drops the packets of HTTP/1.x exchanges whose request target matches a predicate: the request, its response and
 * the body parts of either. Packets that are not part of a recognised HTTP message pass. Uses an
 * {@link HttpStreamDecoder}, so it must see the packets of a connection in order and is not thread safe.
 */
public final class HttpRequestFilter implements PacketFilter {

    private final HttpStreamDecoder decoder = new HttpStreamDecoder();
    private final Predicate<String> excludedTarget;

    /**
     * @param excludedTarget tested against the request target, e.g. {@code /q/dev-ui/devui-data.js}
     */
    public HttpRequestFilter(Predicate<String> excludedTarget) {
        this.excludedTarget = excludedTarget;
    }

    @Override
    public boolean accept(CapturedPacket packet) {
        return !excludes(decoder.decode(packet.linkType(), packet.packet().data()));
    }

    // Whether the summary belongs to an excluded exchange.
    public boolean excludes(PacketSummary summary) {
        if (summary.http() != null && summary.http().isRequest()) {
            return excludedTarget.test(summary.http().target());
        }
        HttpExchange exchange = summary.exchange();
        if (exchange != null) {
            String[] parts = exchange.request().split(" ", 3);
            return parts.length > 1 && excludedTarget.test(parts[1]);
        }
        return false;
    }
}
