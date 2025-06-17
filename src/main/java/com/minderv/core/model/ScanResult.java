package com.minderv.core.model;

import java.util.List;

public record ScanResult(
        List<PortInfo> openPorts,
        List<Vulnerability> vulnerabilities
) {
    public record PortInfo(int port, String state, String service) {}
    public record Vulnerability(String service, String cve, String description, String severity) {}
}