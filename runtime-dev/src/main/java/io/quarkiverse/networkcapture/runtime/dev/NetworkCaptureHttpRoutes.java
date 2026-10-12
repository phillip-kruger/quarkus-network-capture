package io.quarkiverse.networkcapture.runtime.dev;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import io.quarkiverse.networkcapture.runtime.NetworkCaptureConfig;
import io.quarkus.vertx.http.runtime.VertxHttpBuildTimeConfig;
import io.quarkus.vertx.http.runtime.filters.Filters;
import io.vertx.core.net.SocketAddress;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

/**
 * The HTTP side of the Dev UI page: the filter that reports the Dev UI's and Dev MCP's connections to
 * {@link DevUiConnections}, and the route that serves capture files for download. The extension does not require
 * the HTTP layer, so this bean is registered only when the layer is present and the routes are added from its
 * startup events rather than from build items. Dev mode only.
 */
@ApplicationScoped
public class NetworkCaptureHttpRoutes {

    // Relative to the non-application root path, like the Dev UI itself; the page derives the same path from its own.
    static final String DOWNLOAD_PATH = "network-capture/download";

    private final NetworkCaptureConfig config;
    private final VertxHttpBuildTimeConfig httpConfig;

    public NetworkCaptureHttpRoutes(NetworkCaptureConfig config, VertxHttpBuildTimeConfig httpConfig) {
        this.config = config;
        this.httpConfig = httpConfig;
    }

    void filters(@Observes Filters filters) {
        filters.register(this::track, 10_000);
    }

    void routes(@Observes Router router) {
        router.get(downloadPath() + "/:file").handler(new CaptureDownloadHandler(config));
    }

    private void track(RoutingContext ctx) {
        String path = ctx.request().path();
        if (DevUiConnections.isDevMcpPath(path)
                || (DevUiConnections.isDevUiPath(path) && "websocket".equalsIgnoreCase(ctx.request().getHeader("Upgrade")))) {
            SocketAddress local = ctx.request().localAddress();
            SocketAddress remote = ctx.request().remoteAddress();
            if (local != null && remote != null && local.isInetSocket() && remote.isInetSocket()) {
                int localPort = local.port();
                int remotePort = remote.port();
                if (DevUiConnections.opened(localPort, remotePort)) {
                    ctx.request().connection().closeHandler(v -> DevUiConnections.closed(localPort, remotePort));
                }
            }
        }
        ctx.next();
    }

    // The download path under the non-application root, resolved the way the HTTP layer resolves it: the
    // non-application root is absolute when it starts with a slash and relative to the HTTP root otherwise.
    private String downloadPath() {
        String nonApplicationRoot = httpConfig.nonApplicationRootPath();
        String base = nonApplicationRoot.startsWith("/") ? nonApplicationRoot
                : httpConfig.rootPath().replaceAll("/+$", "") + "/" + nonApplicationRoot;
        return base.replaceAll("/+$", "") + "/" + DOWNLOAD_PATH;
    }
}
