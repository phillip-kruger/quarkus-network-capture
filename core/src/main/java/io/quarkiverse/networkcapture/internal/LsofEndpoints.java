package io.quarkiverse.networkcapture.internal;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import io.quarkiverse.networkcapture.CaptureException;

/**
 * macOS (and any system with lsof): local ports from {@code lsof -nP -a -p <pid> -i -F Pn}.
 * <p>
 * References: the <a href="https://github.com/lsof-org/lsof/blob/master/Lsof.8">lsof manual</a>, section
 * "OUTPUT FOR OTHER PROGRAMS", which defines the {@code -F} field output: one field per line, the first character
 * being the field identifier ({@code p} process id, {@code f} descriptor, {@code P} protocol, {@code n} name).
 */
public final class LsofEndpoints implements ProcessEndpoints {

    private final long pid;

    public LsofEndpoints(long pid) {
        this.pid = pid;
    }

    @Override
    public void scan(Set<Endpoint> tcp, Set<Endpoint> udp) {
        String output;
        try {
            Process process = new ProcessBuilder("lsof", "-nP", "-a", "-p", Long.toString(pid), "-i", "-F", "Pn")
                    .redirectErrorStream(true).start();
            try (InputStream in = process.getInputStream()) {
                output = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
            if (!process.waitFor(10, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                throw new CaptureException("lsof did not finish");
            }
        } catch (IOException e) {
            throw new CaptureException("Unable to run lsof: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new CaptureException("Interrupted while running lsof", e);
        }
        parse(output, tcp, udp);
    }

    /**
     * Parses {@code lsof -F Pn} output: one field per line, {@code P} is the protocol and {@code n} the name,
     * e.g. {@code *:8080}, {@code 127.0.0.1:5432->127.0.0.1:50000} or {@code [::1]:8080}. Only the local side of
     * a connection, the part before the arrow, is an endpoint of this process.
     */
    static void parse(String output, Set<Endpoint> tcp, Set<Endpoint> udp) {
        String protocol = null;
        for (String line : output.split("\n")) {
            if (line.startsWith("P")) {
                protocol = line.substring(1).trim();
            } else if (line.startsWith("n") && protocol != null) {
                String local = line.substring(1).trim();
                int arrow = local.indexOf("->");
                if (arrow >= 0) {
                    local = local.substring(0, arrow);
                }
                int colon = local.lastIndexOf(':');
                if (colon < 0) {
                    continue;
                }
                int port;
                try {
                    port = Integer.parseInt(local.substring(colon + 1));
                } catch (NumberFormatException e) {
                    continue;
                }
                if (protocol.equals("TCP")) {
                    tcp.add(Endpoint.of(local.substring(0, colon), port));
                } else if (protocol.equals("UDP")) {
                    udp.add(Endpoint.of(local.substring(0, colon), port));
                }
            }
        }
    }
}
