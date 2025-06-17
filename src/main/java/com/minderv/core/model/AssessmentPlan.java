package com.minderv.core.model;

import java.time.LocalDateTime;
import java.util.List;

public record AssessmentPlan(
        String target,
        LocalDateTime startTime,
        LocalDateTime endTime,
        List<String> methods,
        List<String> resources
) {}