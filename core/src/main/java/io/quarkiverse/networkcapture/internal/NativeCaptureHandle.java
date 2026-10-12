package io.quarkiverse.networkcapture.internal;

import io.quarkiverse.networkcapture.CaptureException;
import io.quarkiverse.networkcapture.CaptureHandle;
import io.quarkiverse.networkcapture.CaptureInterface;
import io.quarkiverse.networkcapture.CaptureOptions;
import io.quarkiverse.networkcapture.CapturePermissionException;
import io.quarkiverse.networkcapture.LinkType;
import io.smallrye.common.os.OS;

/**
 * A capture handle backed by a file descriptor, which is what carries the capture privilege and what the privileged
 * helper passes to the application.
 */
public interface NativeCaptureHandle extends CaptureHandle {

    int fd();

    /**
     * Opens one interface directly, which requires the process to be privileged.
     *
     * @throws CapturePermissionException when the OS refuses because of missing privileges
     */
    static CaptureHandle open(CaptureInterface networkInterface, CaptureOptions options) {
        return switch (OS.current()) {
            case LINUX -> LinuxPacketSocket.open(networkInterface, options);
            case MAC -> MacOsBpf.open(networkInterface, options);
            default -> throw new CaptureException("Packet capture is not supported on " + OS.current());
        };
    }

    /**
     * Wraps a capture file descriptor opened elsewhere, typically received from the privileged helper.
     */
    static CaptureHandle adopt(int fd, CaptureInterface networkInterface, LinkType linkType, int snapLen) {
        return switch (OS.current()) {
            case LINUX -> LinuxPacketSocket.adopt(fd, networkInterface, linkType, snapLen);
            case MAC -> MacOsBpf.adopt(fd, networkInterface, linkType, snapLen);
            default -> throw new CaptureException("Packet capture is not supported on " + OS.current());
        };
    }
}
