package io.quarkiverse.networkcapture.internal;

import java.util.List;
import java.util.Map;

import io.quarkiverse.networkcapture.Capture;
import io.quarkiverse.networkcapture.CaptureHandle;

public record OpenResult(List<CaptureHandle> handles, Map<String, String> skipped) implements Capture.Result {
}
