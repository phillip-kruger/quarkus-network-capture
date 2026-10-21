package io.quarkiverse.networkcapture.runtime.dev;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import jakarta.inject.Inject;

import io.quarkiverse.networkcapture.runtime.NetworkCaptureConfig;
import io.quarkus.runtime.annotations.DevMCPEnableByDefault;
import io.quarkus.runtime.annotations.JsonRpcDescription;
import io.smallrye.common.os.OS;
import io.smallrye.mutiny.Multi;
import io.quarkiverse.networkcapture.Capture;
import io.quarkiverse.networkcapture.CaptureOptions;
import io.quarkiverse.networkcapture.CapturePermissionException;
import io.quarkiverse.networkcapture.Elevation;
import io.quarkiverse.networkcapture.Packet;

/**
 * Backend of the Dev UI page. The methods with a description are also Dev MCP tools, so an AI agent connected to the
 * application can capture traffic and read what was captured; the ones an agent needs for that are enabled by default,
 * deleting files is not.
 */
public class NetworkCaptureJsonRpcService {

    private final NetworkCaptureConfig config;
    private final Redaction redaction;

    public NetworkCaptureJsonRpcService(NetworkCaptureConfig config) {
        this.config = config;
        this.redaction = new Redaction(config.redactHeaders(), config.redactQueryParameters());
    }

    @DevMCPEnableByDefault
    @JsonRpcDescription("Capture settings: platform, directory where capture files are written, elevation mechanism and setup hint")
    public Messages.Settings settings() {
        return new Messages.Settings(OS.current().name(), directory().toAbsolutePath().toString(), elevation().name(),
                setupHint(), config.applicationOnly(), config.excludeDevUi());
    }

    @DevMCPEnableByDefault
    @JsonRpcDescription("Start capturing the application's network traffic on all interfaces that are up, to a new pcapng file. "
            + "Returns status 'started', 'permission-required' when the process lacks capture privileges, or 'error'. "
            + "This tool never runs the privileged helper: on 'permission-required', ask the user to press Start capture "
            + "on the Network Capture page of the Dev UI, or to run the one-time command in 'setupHint', then call it again. "
            + "Once started, exercise the application and read the packets with 'packets'")
    public Messages.StartResult start(
            @JsonRpcDescription("Keep only packets to or from this application's sockets") boolean applicationOnly,
            @JsonRpcDescription("Leave the Dev UI's and Dev MCP's own traffic (their websocket and HTTP exchanges) out of the capture") boolean excludeDevUi) {
        return doStart(false, applicationOnly, excludeDevUi);
    }

    /**
     * The Dev UI page's start. It has no description, so it is not a Dev MCP tool: running the privileged helper,
     * which runs as root and may not even prompt when sudo has cached credentials or a NOPASSWD rule, must be the
     * user's decision, taken by pressing the button on the page.
     *
     * @param elevate whether to fall back to the privileged helper when the direct open is refused
     */
    public Messages.StartResult startFromDevUi(boolean elevate, boolean applicationOnly, boolean excludeDevUi) {
        return doStart(elevate, applicationOnly, excludeDevUi);
    }

    private Messages.StartResult doStart(boolean elevate, boolean applicationOnly, boolean excludeDevUi) {
        CaptureOptions options = CaptureOptions.builder().snapLen(config.snapLen()).promiscuous(config.promiscuous())
                .elevation(elevate ? elevation() : null).helperTimeout(config.helperTimeout()).build();
        try {
            CaptureManager.INSTANCE.start(options, directory(), applicationOnly, excludeDevUi);
            return Messages.StartResult.started();
        } catch (CapturePermissionException e) {
            return new Messages.StartResult("permission-required", e.getMessage(), elevation().name(), setupHint());
        } catch (RuntimeException e) {
            return Messages.StartResult.error(e.getMessage() == null ? e.toString() : e.getMessage());
        }
    }

    @DevMCPEnableByDefault
    @JsonRpcDescription("Stop the running capture and close its file; the packets stay readable with 'packets'")
    public Messages.CaptureStatus stop() {
        CaptureManager.INSTANCE.stop();
        return status();
    }

    @DevMCPEnableByDefault
    @JsonRpcDescription("Status of the capture: whether it is running, the file being written, packet and byte counts per interface")
    public Messages.CaptureStatus status() {
        return CaptureManager.INSTANCE.status();
    }

    // Label shown on the Dev UI card.
    public String statusLabel() {
        return CaptureManager.INSTANCE.isRunning() ? "capturing" : "";
    }

    public Multi<Messages.CaptureStatus> streamStatus() {
        return Multi.createFrom().ticks().every(Duration.ofSeconds(1)).map(t -> status());
    }

    /**
     * Streams the rows of the packet list, one batch every 250 milliseconds, starting with the rows the page has not
     * seen yet: everything after packet number {@code after}, so that a page that reconnects or opens late catches up.
     *
     * @param hideDevUi whether to leave out the Dev UI's own traffic
     * @param after the last packet number the page has, or 0
     */
    public Multi<Messages.PacketBatch> streamPackets(boolean hideDevUi, long after) {
        long[] cursor = { after };
        return Multi.createFrom().ticks().every(Duration.ofMillis(250)).map(t -> {
            Messages.PacketBatch batch = CaptureManager.INSTANCE.rows(cursor[0], hideDevUi, MAX_BATCH);
            if (!batch.packets().isEmpty()) {
                cursor[0] = batch.packets().get(batch.packets().size() - 1).no();
            }
            return batch;
        });
    }

    private static final int MAX_BATCH = 200;

    @DevMCPEnableByDefault
    @JsonRpcDescription("Packets of the running or last capture, oldest first, without the Dev UI's own traffic. Each "
            + "packet has a number, time, addresses, protocol and a one-line summary; packets carrying HTTP/1.x also have "
            + "the method, URL, status, headers and body (decoded, chunking removed) and a link to the matching request or "
            + "response. Credential headers such as Authorization and Cookie, and credential query parameters such as "
            + "access_token, are redacted. Returns at most 'max' packets "
            + "after packet number 'after'; to page, pass the last number received")
    public Messages.PacketBatch packets(
            @JsonRpcDescription("Return only packets numbered after this one; 0 for the first") long after,
            @JsonRpcDescription("Return only packets that carry HTTP") boolean onlyHttp,
            @JsonRpcDescription("Maximum number of packets to return, at most 200") int max) {
        int limit = max <= 0 ? MAX_BATCH : Math.min(max, MAX_BATCH);
        List<Messages.PacketRow> packets = new ArrayList<>();
        long cursor = after;
        Messages.PacketBatch batch;
        do {
            batch = CaptureManager.INSTANCE.rows(cursor, true, MAX_BATCH);
            for (Messages.PacketRow row : batch.packets()) {
                if (!onlyHttp || row.http() != null) {
                    packets.add(redaction.apply(row));
                    if (packets.size() == limit) {
                        return new Messages.PacketBatch(batch.running(), batch.dropped(), packets);
                    }
                }
                cursor = row.no();
            }
        } while (!batch.packets().isEmpty());
        return new Messages.PacketBatch(batch.running(), batch.dropped(), packets);
    }

    @DevMCPEnableByDefault
    @JsonRpcDescription("List the capture files in the capture directory, newest first")
    public List<Messages.CaptureFile> listFiles() {
        return CaptureManager.INSTANCE.files(directory());
    }

    @JsonRpcDescription("Delete a capture file")
    public boolean deleteFile(@JsonRpcDescription("File name as returned by listFiles") String name) {
        return CaptureManager.INSTANCE.delete(directory(), name);
    }

    private Path directory() {
        return Path.of(config.directory());
    }

    private Elevation elevation() {
        String value = config.elevation().trim().toLowerCase(Locale.ROOT);
        return value.equals("auto") ? Elevation.detect() : Elevation.valueOf(value.toUpperCase(Locale.ROOT));
    }

    private static String setupHint() {
        return switch (OS.current()) {
            case LINUX -> "To capture without a prompt, grant the capability once to the JDK you run dev mode with: "
                    + "sudo setcap cap_net_raw+ep " + Path.of(System.getProperty("java.home"), "bin", "java");
            case MAC -> "To capture without a prompt, install Wireshark's ChmodBPF (included in the Wireshark "
                    + "installer) and make sure your user is in the access_bpf group.";
            default -> "Packet capture is not supported on " + OS.current() + ".";
        };
    }
}
