package com.minderv.core.model;

import java.util.List;

public record RiskAssessment(
        double riskScore,
        String protectionEffectiveness,
        List<String> recommendations
) {}