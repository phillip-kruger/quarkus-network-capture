package io.quarkiverse.networkcapture.internal;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.jboss.logging.Logger;

import io.quarkiverse.networkcapture.Capture;
import io.quarkiverse.networkcapture.CaptureException;
import io.quarkiverse.networkcapture.CaptureHandle;
import io.quarkiverse.networkcapture.CaptureInterface;
import io.quarkiverse.networkcapture.CaptureOptions;
import io.quarkiverse.networkcapture.Elevation;
import io.quarkiverse.networkcapture.LinkType;
import io.smallrye.common.constraint.Assert;
import io.smallrye.common.cpu.CPU;
import io.smallrye.common.os.OS;
import io.smallrye.common.process.AbnormalExitException;
import io.smallrye.common.process.AbstractExecutionException;
import io.smallrye.common.process.ProcessBuilder;
import io.smallrye.common.process.ProcessUtil;
import io.smallrye.common.process.WaitableProcessHandle;
import io.smallrye.ffm.Errno;

/**
 * Spawns {@link PrivilegedOpener} in a separate, elevated JVM and adopts the descriptors it sends back. Used by
 * {@link Capture#open(List, CaptureOptions)} when the direct open is refused.
 * <p>
 * This is the same privilege separation Wireshark uses with its {@code dumpcap} helper, see
 * <a href="https://wiki.wireshark.org/CaptureSetup/CapturePrivileges">Capture Privileges</a>: only a small,
 * short-lived process runs with elevated rights, and hands the capture descriptor to the unprivileged application
 * over a Unix domain socket with {@code SCM_RIGHTS} (<a href="https://man7.org/linux/man-pages/man7/unix.7.html">unix(7)</a>).
 */
public final class PrivilegedLauncher {

    // Launching a process with elevated privileges on the developer's behalf must be visible in the application log.
    private static final Logger LOG = Logger.getLogger(PrivilegedLauncher.class);

    private PrivilegedLauncher() {
    }

    private static final Duration RECEIVE_POLL = Duration.ofMillis(200);

    // What the receiving side learned from the helper.
    private static final class Outcome {
        final List<CaptureHandle> handles = new ArrayList<>();
        final Map<String, String> errors = new LinkedHashMap<>();
        boolean done;
        String failure;
    }

    /**
     * Opens the requested interfaces through the helper. Interfaces the helper cannot open are reported in
     * {@link Capture.Result#skipped()}; the call fails only when none could be opened.
     *
     */
    public static Capture.Result open(List<CaptureInterface> interfaces, CaptureOptions options) {
        Elevation elevation = options.elevation().orElseThrow();
        Duration timeout = options.helperTimeout();
        Path dir;
        try {
            dir = Files.createTempDirectory("quarkus-network-capture-",
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        } catch (IOException e) {
            throw new CaptureException("Unable to create temporary directory", e);
        }
        Path socketPath = dir.resolve("helper.sock");
        int socket = UnixSockets.bind(socketPath);
        Outcome outcome = new Outcome();
        Map<String, CaptureInterface> byName = new LinkedHashMap<>();
        for (CaptureInterface i : interfaces) {
            byName.put(i.name(), i);
        }
        List<String> command = elevation.wrap(command(socketPath, interfaces, options));
        LOG.infof("Opening %s through a privileged helper (%s), which may prompt for a password: %s",
                String.join(", ", byName.keySet()), elevation.name().toLowerCase(Locale.ROOT), String.join(" ", command));
        try {
            ProcessBuilder.newBuilder(command.getFirst(), command.subList(1, command.size()))
                    .whileRunning(process -> receive(process, socket, byName, outcome, timeout))
                    .run();
        } catch (AbnormalExitException e) {
            if (outcome.failure == null) {
                outcome.failure = "Capture helper exited with status " + e.exitCode() + ": " + e.getMessage();
            }
        } catch (AbstractExecutionException e) {
            if (outcome.failure == null) {
                StringBuilder message = new StringBuilder("Unable to run the capture helper");
                for (Throwable t = e; t != null; t = t.getCause()) {
                    if (t.getMessage() != null && message.indexOf(t.getMessage()) < 0) {
                        message.append(": ").append(t.getMessage());
                    }
                }
                outcome.failure = message.toString();
            }
        } finally {
            UnixSockets.close(socket);
            Libc.unlink(socketPath.toString());
            try {
                Files.deleteIfExists(dir);
            } catch (IOException ignored) {
            }
        }
        if (outcome.failure == null && !outcome.done) {
            outcome.failure = "Capture helper exited before completing";
        }
        if (outcome.failure == null && outcome.handles.isEmpty()) {
            outcome.failure = "Capture helper could not open any interface: " + outcome.errors;
        }
        if (outcome.failure != null) {
            outcome.handles.forEach(CaptureHandle::close);
            throw new CaptureException(outcome.failure);
        }
        LOG.infof("Privileged helper opened %d of %d interfaces and exited%s", outcome.handles.size(), interfaces.size(),
                outcome.errors.isEmpty() ? "" : "; could not open " + outcome.errors);
        return new OpenResult(outcome.handles, outcome.errors);
    }

    // Runs on a separate thread while the helper is alive; must not throw.
    private static void receive(WaitableProcessHandle process, int socket, Map<String, CaptureInterface> byName,
            Outcome outcome, Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        try {
            while (!outcome.done) {
                UnixSockets.Message message = UnixSockets.receive(socket, RECEIVE_POLL);
                if (message == null) {
                    if (!process.isAlive()) {
                        // Give any datagram sent right before exit a chance to arrive
                        message = UnixSockets.receive(socket, RECEIVE_POLL);
                        if (message == null) {
                            return;
                        }
                    } else if (System.nanoTime() > deadline) {
                        outcome.failure = "Timed out waiting for the capture helper";
                        process.destroy();
                        return;
                    } else {
                        continue;
                    }
                }
                handle(message, byName, outcome);
            }
        } catch (RuntimeException e) {
            outcome.failure = e.getMessage();
            process.destroy();
        }
    }

    private static void handle(UnixSockets.Message message, Map<String, CaptureInterface> byName, Outcome outcome) {
        String[] parts = new String(message.payload(), StandardCharsets.UTF_8).split(" ", 4);
        switch (parts[0]) {
            case "OK" -> {
                CaptureInterface iface = byName.get(parts[1]);
                if (iface == null || message.fds().length != 1) {
                    throw new CaptureException("Unexpected helper message: " + String.join(" ", parts));
                }
                outcome.handles.add(NativeCaptureHandle.adopt(message.fds()[0], iface,
                        LinkType.fromPcapValue(Integer.parseInt(parts[2])), Integer.parseInt(parts[3])));
            }
            case "ERR" -> outcome.errors.put(parts[1],
                    parts.length > 2 ? String.join(" ", Arrays.copyOfRange(parts, 2, parts.length)) : "unknown error");
            case "DONE" -> outcome.done = true;
            default -> throw new CaptureException("Unexpected helper message: " + String.join(" ", parts));
        }
    }

    private static List<String> command(Path socketPath, List<CaptureInterface> interfaces, CaptureOptions options) {
        List<String> command = new ArrayList<>();
        command.add(ProcessUtil.pathOfJava().toAbsolutePath().toString());
        command.add("--enable-native-access=ALL-UNNAMED");
        command.add("-cp");
        command.add(classpath());
        command.add(PrivilegedOpener.class.getName());
        command.add(socketPath.toString());
        command.add(Integer.toString(options.snapLen()));
        command.add(Boolean.toString(options.promiscuous()));
        for (CaptureInterface i : interfaces) {
            command.add(i.name());
        }
        return command;
    }

    /**
     * The helper needs this library, SmallRye FFM and the SmallRye Common modules FFM uses at runtime; each jar is
     * located through a class it contains.
     */
    private static String classpath() {
        List<String> entries = new ArrayList<>();
        for (Class<?> anchor : List.of(PrivilegedOpener.class, Errno.class, OS.class, CPU.class, Assert.class)) {
            try {
                String entry = Path.of(anchor.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
                if (!entries.contains(entry)) {
                    entries.add(entry);
                }
            } catch (URISyntaxException | NullPointerException e) {
                throw new CaptureException("Unable to locate the jar of " + anchor.getName() + " for the helper process", e);
            }
        }
        return String.join(File.pathSeparator, entries);
    }
}
