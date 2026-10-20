package io.quarkiverse.networkcapture.internal;

import java.util.Set;

/**
 * Enumerates the local endpoints of a process's TCP and UDP sockets.
 */
public interface ProcessEndpoints {

    /**
     * Adds the local endpoint of every open socket of the process to the given sets.
     */
    void scan(Set<Endpoint> tcp, Set<Endpoint> udp);
}
