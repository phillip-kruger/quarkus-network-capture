package io.quarkiverse.networkcapture;

/**
 * Receives packets after a {@link CaptureSession} has written them. Called on the session's writer thread, one packet
 * at a time and never concurrently with the filter or other listeners, so an implementation needs no synchronisation
 * of its own but must not block: nothing is written while it runs. An exception thrown by a listener is ignored.
 */
@FunctionalInterface
public interface PacketListener {

    void onPacket(CapturedPacket packet);
}
