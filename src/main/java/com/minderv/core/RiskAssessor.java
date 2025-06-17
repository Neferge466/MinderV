package com.minderv.core;

import com.minderv.core.model.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;
import java.util.Map;

public class RiskAssessor {
    private static final Logger logger = LogManager.getLogger(RiskAssessor.class);

    public RiskAssessment assess(NetworkSystem system, ScanResult scanResult) {
        // 处理空扫描结果
        if (scanResult.vulnerabilities().isEmpty() && scanResult.openPorts().isEmpty()) {
            logger.warn("扫描结果为空，使用最低风险评分");
            return new RiskAssessment(
                    0.1, // 最低风险评分
                    evaluateProtections(system.securityConfigs()),
                    List.of("扫描未发现任何开放端口或漏洞，但仍建议进行人工验证")
            );
        }

        double baseScore = calculateBaseScore(scanResult);
        double impact = calculateImpactFactor(system);
        List<String> recommendations = generateRecommendations(scanResult);

        return new RiskAssessment(
                baseScore * impact,
                evaluateProtections(system.securityConfigs()),
                recommendations
        );
    }

    private double calculateBaseScore(ScanResult result) {
        // 处理空漏洞列表
        if (result.vulnerabilities().isEmpty()) {
            return 0.1; // 无漏洞时的基础评分
        }

        return result.vulnerabilities().stream()
                .mapToDouble(v -> switch(v.severity()) {
                    case "Critical" -> 1.0;
                    case "High" -> 0.8;
                    case "Medium" -> 0.5;
                    default -> 0.2;
                })
                .average()
                .orElse(0.1); // 空列表时的默认值
    }

    private double calculateImpactFactor(NetworkSystem system) {
        return system.securityConfigs().containsKey("encryption") ? 0.5 : 1.0;
    }

    private List<String> generateRecommendations(ScanResult result) {
        return result.vulnerabilities().stream()
                .map(v -> "修复 " + v.cve() + ": " + v.description())
                .toList();
    }

    private String evaluateProtections(Map<String, String> configs) {
        return configs.containsKey("firewall") ? "Effective" : "Inadequate";
    }
}