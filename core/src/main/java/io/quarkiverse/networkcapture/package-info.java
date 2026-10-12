/**
 * The API of the capture library, and the only package meant to be used by callers; everything under
 * {@code io.quarkiverse.networkcapture.internal} is implementation and may change without notice.
 * <p>
 * List interfaces with {@link io.quarkiverse.networkcapture.CaptureInterfaces}, open handles with
 * {@link io.quarkiverse.networkcapture.Capture} and {@link io.quarkiverse.networkcapture.CaptureOptions}, which can name an
 * {@link io.quarkiverse.networkcapture.Elevation} for a helper process to use when the application lacks capture privileges,
 * and run a
 * {@link io.quarkiverse.networkcapture.CaptureSession} that writes a pcapng file, optionally through a
 * {@link io.quarkiverse.networkcapture.PacketFilter} such as {@link io.quarkiverse.networkcapture.ApplicationTrafficFilter}.
 *
 * <h2>Threading</h2>
 * A {@link io.quarkiverse.networkcapture.CaptureSession} owns all the threads involved, and all of them are daemon threads:
 * one reader thread per interface, named {@code network-capture-<interface>}, that polls the handle and queues packets,
 * and one writer thread, named {@code network-capture-writer}, that holds each packet for the filter's hold time, asks the
 * filter, writes the file and notifies listeners. Consequently:
 * <ul>
 * <li>{@link io.quarkiverse.networkcapture.PacketFilter#accept} and {@link io.quarkiverse.networkcapture.PacketListener#onPacket} run on
 * the writer thread, one packet at a time, never concurrently with each other. They need no synchronisation of their
 * own, but must return quickly: while they run, nothing is written.</li>
 * <li>The session's other methods may be called from any thread. {@link io.quarkiverse.networkcapture.CaptureSession#stop()}
 * blocks until the reader and writer threads have finished, which takes up to the hold time plus a poll timeout.</li>
 * <li>A {@link io.quarkiverse.networkcapture.CaptureHandle} may be created on one thread and polled on another, but
 * {@link io.quarkiverse.networkcapture.CaptureHandle#poll} must not be called concurrently. A session takes ownership of its
 * handles; do not poll them yourself once a session uses them.</li>
 * <li>{@link io.quarkiverse.networkcapture.Capture#open(java.util.List, CaptureOptions)} blocks the calling thread while the
 * helper process runs, which includes the time a user takes to answer the password prompt, bounded by the options'
 * helper timeout.</li>
 * </ul>
 * The library creates no other threads and uses no virtual threads.
 */
package io.quarkiverse.networkcapture;
