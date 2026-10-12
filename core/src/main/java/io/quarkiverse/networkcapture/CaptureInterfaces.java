package io.quarkiverse.networkcapture;

import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;


public final class CaptureInterfaces {

    private CaptureInterfaces() {
    }

    /**
     * The interfaces that are up, which is what a capture usually opens: only an interface that is up can carry
     * traffic, and {@link Capture#open} reports the ones it cannot open.
     */
    public static List<CaptureInterface> listUp() {
        return list().stream().filter(CaptureInterface::up).toList();
    }

    /**
     * Every interface the OS reports, up or not.
     */
    public static List<CaptureInterface> list() {
        List<CaptureInterface> result = new ArrayList<>();
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (ni.isVirtual()) {
                    continue;
                }
                result.add(new DefaultCaptureInterface(ni.getName(), ni.getIndex(), ni.isLoopback(), ni.isUp()));
            }
        } catch (SocketException e) {
            throw new CaptureException("Unable to list network interfaces", e);
        }
        result.sort(Comparator.comparingInt(CaptureInterface::index));
        return result;
    }

}
