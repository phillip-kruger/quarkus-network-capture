package io.quarkiverse.networkcapture.runtime.dev;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Remembers the TCP connections of the Dev UI's websockets and of the Dev MCP server, so that the capture and the
 * live packet view can leave them out. Without this, streaming packet summaries to the browser over loopback
 * produces packets that are themselves streamed, and an agent reading the capture sees its own tool calls.
 * <p>
 * Of the Dev UI's traffic only websocket connections are tracked. A websocket connection is dedicated to the Dev UI,
 * whereas a plain HTTP keep-alive connection that served a Dev UI page is reused by the browser for requests to the
 * application itself, so excluding it would hide application traffic. A Dev MCP connection belongs to an agent's MCP
 * client, which talks to nothing else, so every Dev MCP connection is tracked; the exclusion by request target alone
 * would miss the response to the tool call that started the capture. The connections are reported by
 * {@link NetworkCaptureHttpRoutes}, which sees the requests; this class holds no HTTP types so that it loads without the HTTP
 * layer. Dev mode only.
 */
public final class DevUiConnections {

    // Closed connections stay known this long, so that packets held by the capture filter still match.
    private static final long GRACE_NANOS = Duration.ofSeconds(15).toNanos();
    private static final long OPEN = 0;

    // Port pair to the time the connection closed, or OPEN.
    private static final Map<Long, Long> CONNECTIONS = new ConcurrentHashMap<>();

    private DevUiConnections() {
    }

    // Whether a request path or target is the Dev UI's or the Dev MCP server's.
    public static boolean isDevUiPath(String path) {
        return path.contains("/dev-ui") || isDevMcpPath(path);
    }

    // Whether a request path is the Dev MCP server's.
    static boolean isDevMcpPath(String path) {
        return path.contains("/dev-mcp");
    }

    /**
     * Records a connection as the Dev UI's; returns whether it was new, so that the caller registers its close once.
     */
    static boolean opened(int localPort, int remotePort) {
        boolean added = CONNECTIONS.put(key(localPort, remotePort), OPEN) == null;
        expire();
        return added;
    }

    static void closed(int localPort, int remotePort) {
        CONNECTIONS.put(key(localPort, remotePort), System.nanoTime());
    }

    // Whether a TCP segment between these two ports belongs to a Dev UI websocket or Dev MCP connection.
    public static boolean isDevUiConnection(int portA, int portB) {
        return CONNECTIONS.containsKey(key(portA, portB)) || CONNECTIONS.containsKey(key(portB, portA));
    }

    private static void expire() {
        long now = System.nanoTime();
        CONNECTIONS.values().removeIf(closedAt -> closedAt != OPEN && now - closedAt > GRACE_NANOS);
    }

    private static long key(int localPort, int remotePort) {
        return ((long) localPort << 16) | remotePort;
    }
}
