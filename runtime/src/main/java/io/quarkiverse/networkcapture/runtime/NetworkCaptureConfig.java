package io.quarkiverse.networkcapture.runtime;

import java.time.Duration;

import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

@ConfigMapping(prefix = "quarkus.network-capture")
@ConfigRoot(phase = ConfigPhase.RUN_TIME)
public interface NetworkCaptureConfig {

    /**
     * Directory where capture files are written. Relative paths are resolved against the working directory.
     */
    @WithDefault("target/pcap")
    String directory();

    /**
     * Maximum number of bytes captured per packet.
     */
    @WithDefault("262144")
    int snapLen();

    /**
     * Default for the "only this application's traffic" option: keep only TCP and UDP packets whose source or
     * destination port belongs to a socket of this process.
     */
    @WithDefault("true")
    boolean applicationOnly();

    /**
     * Default for the "exclude Dev UI traffic" option: leave the Dev UI's own traffic out of the capture file, that
     * is its websocket connections and its HTTP requests and responses. Application requests on a connection the
     * browser also used for the Dev UI are kept.
     */
    @WithDefault("true")
    boolean excludeDevUi();

    /**
     * Whether to put captured interfaces into promiscuous mode.
     */
    @WithDefault("false")
    boolean promiscuous();

    /**
     * How the helper process that opens the capture acquires root when the application itself lacks the
     * privilege: {@code auto}, {@code sudo}, {@code pkexec} (Linux desktop prompt) or {@code osascript}
     * (macOS prompt). {@code auto} picks {@code osascript} on macOS and {@code pkexec} or {@code sudo} on Linux.
     */
    @WithDefault("auto")
    String elevation();

    /**
     * How long to wait for the privileged helper, which includes the time the user takes to enter a password.
     */
    @WithDefault("2m")
    Duration helperTimeout();
}
