package io.quarkiverse.networkcapture;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import io.quarkiverse.networkcapture.internal.NativeCaptureHandle;
import io.quarkiverse.networkcapture.internal.OpenResult;
import io.quarkiverse.networkcapture.internal.PrivilegedLauncher;

/**
 * Opens capture handles on the current operating system, the way {@code pcap_create} and {@code pcap_activate} do
 * in libpcap, but through the JDK's Foreign Function &amp; Memory API rather than a native library.
 * <p>
 * Opening needs a privilege ({@code CAP_NET_RAW} on Linux, access to {@code /dev/bpf*} on macOS). When the process
 * lacks it and the options name an {@link Elevation}, a short lived helper process acquires the privilege, opens
 * the handles and passes them back.
 * <p>
 * References: <a href="https://www.tcpdump.org/manpages/pcap.3pcap.html">pcap(3PCAP)</a>;
 * <a href="https://openjdk.org/jeps/454">JEP 454: Foreign Function &amp; Memory API</a>.
 */
public final class Capture {

    private Capture() {
    }

    /**
     * What {@link #open(List, CaptureOptions)} managed to open.
     */
    public interface Result {

        /**
         * One handle per interface that could be opened.
         */
        List<CaptureHandle> handles();

        /**
         * The interfaces that could not be opened, with the reason.
         */
        Map<String, String> skipped();
    }

    /**
     * Opens every interface that is up with the default options; see {@link #open(List, CaptureOptions)}.
     */
    public static Result open() {
        return open(CaptureInterfaces.listUp(), CaptureOptions.DEFAULT);
    }

    /**
     * Opens every interface that is up; see {@link #open(List, CaptureOptions)}.
     */
    public static Result open(CaptureOptions options) {
        return open(CaptureInterfaces.listUp(), options);
    }

    /**
     * Opens the interfaces, directly when the process is privileged, otherwise through the helper process when the
     * options name an {@link Elevation}. Interfaces that cannot be opened for a reason other than privilege are
     * skipped and reported in the result; the call fails only when none could be opened.
     *
     * @throws CapturePermissionException when the direct open is refused and the options name no elevation
     */
    public static Result open(List<CaptureInterface> interfaces, CaptureOptions options) {
        List<CaptureHandle> handles = new ArrayList<>();
        Map<String, String> skipped = new LinkedHashMap<>();
        try {
            for (CaptureInterface i : interfaces) {
                try {
                    handles.add(NativeCaptureHandle.open(i, options));
                } catch (CapturePermissionException e) {
                    throw e;
                } catch (CaptureException e) {
                    skipped.put(i.name(), e.getMessage());
                }
            }
        } catch (CapturePermissionException e) {
            handles.forEach(CaptureHandle::close);
            if (options.elevation().isEmpty()) {
                throw e;
            }
            return PrivilegedLauncher.open(interfaces, options);
        } catch (RuntimeException e) {
            handles.forEach(CaptureHandle::close);
            throw e;
        }
        if (handles.isEmpty()) {
            throw new CaptureException("No interface could be opened: " + skipped);
        }
        return new OpenResult(handles, skipped);
    }
}
