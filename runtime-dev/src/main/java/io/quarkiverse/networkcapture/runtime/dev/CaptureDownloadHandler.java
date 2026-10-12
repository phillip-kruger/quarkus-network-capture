package io.quarkiverse.networkcapture.runtime.dev;

import java.nio.file.Files;
import java.nio.file.Path;

import io.quarkiverse.networkcapture.runtime.NetworkCaptureConfig;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpHeaders;
import io.vertx.ext.web.RoutingContext;

/**
 * Serves capture files from the configured directory. Dev mode only.
 */
class CaptureDownloadHandler implements Handler<RoutingContext> {

    private final NetworkCaptureConfig config;

    CaptureDownloadHandler(NetworkCaptureConfig config) {
        this.config = config;
    }

    @Override
    public void handle(RoutingContext ctx) {
        Path file;
        try {
            file = CaptureManager.resolveFile(Path.of(config.directory()), ctx.pathParam("file"));
        } catch (IllegalArgumentException e) {
            ctx.response().setStatusCode(400).end(e.getMessage());
            return;
        }
        if (!Files.isRegularFile(file)) {
            ctx.response().setStatusCode(404).end();
            return;
        }
        ctx.response()
                .putHeader(HttpHeaders.CONTENT_TYPE, "application/x-pcapng")
                .putHeader("Content-Disposition", "attachment; filename=\"" + file.getFileName() + "\"")
                .sendFile(file.toAbsolutePath().toString());
    }
}
