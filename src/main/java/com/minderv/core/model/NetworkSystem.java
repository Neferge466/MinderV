package com.minderv.core.model;

import java.util.List;
import java.util.Map;

public record NetworkSystem(
        String topology,
        List<DataFlow> dataFlows,
        Map<String, String> securityConfigs,
        List<NetworkInterface> interfaces
) {
    public record DataFlow(String source, String destination, String protocol) {}
    public record NetworkInterface(String name, String address) {}
}