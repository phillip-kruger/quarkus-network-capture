package io.quarkiverse.networkcapture.internal;

import java.util.Set;

/**
 * Enumerates the local TCP and UDP ports of a process's sockets.
 */
public interface ProcessEndpoints {

    /**
     * Adds the ports of every open socket of the process to the given sets.
     */
    void scan(Set<Integer> tcpPorts, Set<Integer> udpPorts);
}
