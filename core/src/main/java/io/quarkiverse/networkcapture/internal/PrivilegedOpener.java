package io.quarkiverse.networkcapture.internal;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;

import io.quarkiverse.networkcapture.CaptureException;
import io.quarkiverse.networkcapture.CaptureInterface;
import io.quarkiverse.networkcapture.CaptureInterfaces;
import io.quarkiverse.networkcapture.CaptureOptions;


/**
 * Entry point of the privileged helper. Opens capture handles and hands their descriptors to the unprivileged
 * parent over a Unix datagram socket, then exits. This is the only code that ever runs with elevated rights.
 * <p>
 * Usage: {@code PrivilegedOpener <socket-path> <snapLen> <promiscuous> <interface>...}
 * <p>
 * Protocol: one datagram per interface, {@code OK <name> <linkType> <snapLen>} carrying the descriptor or
 * {@code ERR <name> <message>}, followed by a final {@code DONE}.
 * <p>
 * References: <a href="https://wiki.wireshark.org/CaptureSetup/CapturePrivileges">Wireshark's capture privileges
 * page</a>, which describes the same separation with {@code dumpcap};
 * <a href="https://man7.org/linux/man-pages/man7/unix.7.html">unix(7)</a> for passing descriptors with
 * {@code SCM_RIGHTS}; <a href="https://man7.org/linux/man-pages/man7/capabilities.7.html">capabilities(7)</a> for
 * why only the {@code socket(2)} call needs {@code CAP_NET_RAW}.
 */
public final class PrivilegedOpener {

    private PrivilegedOpener() {
    }

    private static CaptureInterface byName(String name) {
        return CaptureInterfaces.list().stream().filter(i -> i.name().equals(name)).findFirst()
                .orElseThrow(() -> new CaptureException("No such network interface: " + name));
    }

    public static void main(String[] args) {
        if (args.length < 4) {
            System.err.println("Usage: PrivilegedOpener <socket-path> <snapLen> <promiscuous> <interface>...");
            System.exit(2);
        }
        Path socketPath = Path.of(args[0]);
        CaptureOptions options = CaptureOptions.builder().snapLen(Integer.parseInt(args[1]))
                .promiscuous(Boolean.parseBoolean(args[2])).build();
        int socket = UnixSockets.socket();
        try {
            for (String name : Arrays.copyOfRange(args, 3, args.length)) {
                try {
                    NativeCaptureHandle handle = (NativeCaptureHandle) NativeCaptureHandle.open(byName(name), options);
                    String payload = "OK " + name + " " + handle.linkType().pcapValue() + " " + handle.snapLen();
                    UnixSockets.send(socket, socketPath, payload.getBytes(StandardCharsets.UTF_8),
                            new int[] { handle.fd() });
                    handle.close();
                } catch (RuntimeException e) {
                    String payload = "ERR " + name + " " + e.getMessage();
                    UnixSockets.send(socket, socketPath, payload.getBytes(StandardCharsets.UTF_8), new int[0]);
                }
            }
            UnixSockets.send(socket, socketPath, "DONE".getBytes(StandardCharsets.UTF_8), new int[0]);
        } finally {
            UnixSockets.close(socket);
        }
    }
}
