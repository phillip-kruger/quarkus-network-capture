package io.quarkiverse.networkcapture;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import io.smallrye.common.os.OS;

/**
 * How the privileged helper process acquires root.
 * <p>
 * References: the <a href="https://www.sudo.ws/docs/man/sudo.man/">sudo manual</a> ({@code -n} never prompts);
 * the <a href="https://manpages.debian.org/testing/pkexec/pkexec.1.en.html">pkexec manual</a> (PolicyKit, shows a
 * graphical authentication dialog on Linux desktops); Apple's
 * <a href="https://developer.apple.com/library/archive/technotes/tn2065/_index.html">Technical Note TN2065</a> for
 * {@code do shell script ... with administrator privileges}, including its quoting rules.
 */
public enum Elevation {
    /**
     * {@code sudo -n}: non-interactive, works with cached credentials or a NOPASSWD rule.
     */
    SUDO,
    /**
     * PolicyKit graphical prompt (Linux desktops).
     */
    PKEXEC,
    /**
     * macOS administrator password dialog via {@code osascript}.
     */
    OSASCRIPT;

    /**
     * Picks the mechanism most likely to show a usable prompt on this machine.
     */
    public static Elevation detect() {
        if (OS.MAC.isCurrent()) {
            return OSASCRIPT;
        }
        boolean display = System.getenv("DISPLAY") != null || System.getenv("WAYLAND_DISPLAY") != null;
        if (display && Files.isExecutable(Path.of("/usr/bin/pkexec"))) {
            return PKEXEC;
        }
        return SUDO;
    }

    public List<String> wrap(List<String> command) {
        List<String> result = new ArrayList<>();
        switch (this) {
            case SUDO -> {
                result.add("sudo");
                result.add("-n");
                result.addAll(command);
            }
            case PKEXEC -> {
                result.add("pkexec");
                result.addAll(command);
            }
            case OSASCRIPT -> {
                StringBuilder shell = new StringBuilder();
                for (String arg : command) {
                    if (!shell.isEmpty()) {
                        shell.append(' ');
                    }
                    shell.append('\'').append(arg.replace("'", "'\\''")).append('\'');
                }
                String script = "do shell script \"" + shell.toString().replace("\\", "\\\\").replace("\"", "\\\"")
                        + "\" with administrator privileges";
                result.add("osascript");
                result.add("-e");
                result.add(script);
            }
        }
        return result;
    }
}
