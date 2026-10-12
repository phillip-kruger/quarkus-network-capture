package io.quarkiverse.networkcapture.deployment;

import io.quarkiverse.networkcapture.runtime.dev.NetworkCaptureJsonRpcService;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.Capabilities;
import io.quarkus.deployment.Capability;
import io.quarkus.deployment.IsLocalDevelopment;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.devjsonrpc.spi.JsonRPCProvidersBuildItem;
import io.quarkus.devui.spi.page.CardPageBuildItem;
import io.quarkus.devui.spi.page.Page;

class NetworkCaptureProcessor {

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem("network-capture");
    }

    @BuildStep(onlyIf = IsLocalDevelopment.class)
    CardPageBuildItem devUiCard() {
        CardPageBuildItem card = new CardPageBuildItem();
        card.addPage(Page.webComponentPageBuilder()
                .title("Capture")
                .icon("font-awesome-solid:network-wired")
                .componentLink("qwc-network-capture.js")
                .dynamicLabelJsonRPCMethodName("statusLabel"));
        return card;
    }

    @BuildStep(onlyIf = IsLocalDevelopment.class)
    JsonRPCProvidersBuildItem jsonRpc() {
        return new JsonRPCProvidersBuildItem(NetworkCaptureJsonRpcService.class);
    }

    // The page's HTTP side, a filter that recognises the Dev UI's and Dev MCP's connections and the download route,
    // is registered from a bean that observes the HTTP layer's startup events. The bean exists only when the layer is
    // present, and it is named rather than referenced so that none of its classes is loaded otherwise.
    @BuildStep(onlyIf = IsLocalDevelopment.class)
    void httpSide(Capabilities capabilities, BuildProducer<AdditionalBeanBuildItem> beans) {
        if (capabilities.isPresent(Capability.VERTX_HTTP)) {
            beans.produce(AdditionalBeanBuildItem.builder()
                    .addBeanClass("io.quarkiverse.networkcapture.runtime.dev.NetworkCaptureHttpRoutes")
                    .setUnremovable()
                    .build());
        }
    }
}
