package io.quarkiverse.networkcapture;

public class CaptureException extends RuntimeException {

    public CaptureException(String message) {
        super(message);
    }

    public CaptureException(String message, Throwable cause) {
        super(message, cause);
    }
}
