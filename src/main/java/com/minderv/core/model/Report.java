package com.minderv.core.model;

import java.util.List;

public record Report(
        String executiveSummary,
        List<ScanResult.Vulnerability> findings,
        List<String> recommendations
) {}
