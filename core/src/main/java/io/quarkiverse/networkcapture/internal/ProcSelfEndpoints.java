package io.quarkiverse.networkcapture.internal;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Linux: socket inodes from {@code /proc/self/fd}, resolved to ports through {@code /proc/net/tcp},
 * {@code tcp6}, {@code udp} and {@code udp6}, whose {@code local_address} column is {@code hex-ip:hex-port} and whose
 * tenth column is the socket inode.
 * <p>
 * References: <a href="https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html">proc_pid_fd(5)</a> for the
 * {@code socket:[inode]} link targets; <a href="https://man7.org/linux/man-pages/man5/proc_net.5.html">proc_net(5)</a>
 * for the table layout.
 */
public final class ProcSelfEndpoints implements ProcessEndpoints {

    private static final Path FD_DIR = Path.of("/proc/self/fd");
    private static final List<Path> TCP_TABLES = List.of(Path.of("/proc/net/tcp"), Path.of("/proc/net/tcp6"));
    private static final List<Path> UDP_TABLES = List.of(Path.of("/proc/net/udp"), Path.of("/proc/net/udp6"));

    @Override
    public void scan(Set<Integer> tcpPorts, Set<Integer> udpPorts) {
        Set<String> inodes = new HashSet<>();
        try (Stream<Path> fds = Files.list(FD_DIR)) {
            for (Path fd : fds.toList()) {
                try {
                    String target = Files.readSymbolicLink(fd).toString();
                    if (target.startsWith("socket:[") && target.endsWith("]")) {
                        inodes.add(target.substring(8, target.length() - 1));
                    }
                } catch (IOException ignored) {
                    // the descriptor was closed in the meantime
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        collect(TCP_TABLES, inodes, tcpPorts);
        collect(UDP_TABLES, inodes, udpPorts);
    }

    private static void collect(List<Path> tables, Set<String> inodes, Set<Integer> ports) {
        for (Path table : tables) {
            if (!Files.isReadable(table)) {
                continue;
            }
            try {
                for (String line : Files.readAllLines(table)) {
                    // sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode ...
                    String[] f = line.trim().split("\\s+");
                    if (f.length < 10 || !inodes.contains(f[9])) {
                        continue;
                    }
                    String local = f[1];
                    ports.add(Integer.parseInt(local.substring(local.lastIndexOf(':') + 1), 16));
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }
}
