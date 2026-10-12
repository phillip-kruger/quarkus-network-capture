package io.quarkiverse.networkcapture;

/**
 * Thrown when the operating system refused to hand out a capture handle because the process lacks the
 * required privilege (CAP_NET_RAW on Linux, read access to /dev/bpf* on macOS).
 */
public class CapturePermissionException extends CaptureException {

    public CapturePermissionException(String message) {
        super(message);
    }
}
