package com.minderv.core;

import com.minderv.core.model.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;
import java.util.stream.Collectors;

public class RiskAssessor {
    private static final Logger logger = LogManager.getLogger(RiskAssessor.class);

    // 高风险端口列表
    private static final List<Integer> HIGH_RISK_PORTS = Arrays.asList(22, 23, 135, 139, 445, 1433, 3306, 3389, 5900, 8080);

    // 中等风险端口列表
    private static final List<Integer> MEDIUM_RISK_PORTS = Arrays.asList(21, 25, 53, 80, 443, 8000, 8443, 8888);

    // 关键服务漏洞权重
    private static final Map<String, Double> CRITICAL_VULN_WEIGHTS = Map.of(
            "CVE-2017-0143", 1.5,   // EternalBlue
            "CVE-2021-44228", 1.4,  // Log4Shell
            "CVE-2021-34527", 1.3,  // PrintNightmare
            "CVE-2019-0708", 1.5    // BlueKeep
    );

    public RiskAssessment assess(NetworkSystem system, ScanResult scanResult) {
        // 处理空扫描结果
        if (scanResult.vulnerabilities().isEmpty() && scanResult.openPorts().isEmpty()) {
            logger.warn("扫描结果为空，使用最低风险评分");
            return new RiskAssessment(
                    0.1, // 最低风险评分
                    evaluateProtections(system.securityConfigs()),
                    List.of("扫描未发现任何开放端口或漏洞，但仍建议进行人工验证",
                            "检查防火墙配置确保所有端口都被正确过滤",
                            "定期进行安全扫描以确保系统持续安全")
            );
        }

        // 计算基础风险评分
        double baseScore = calculateBaseScore(scanResult);

        // 计算端口风险
        double portRisk = calculatePortRisk(scanResult.openPorts());

        // 计算影响因子
        double impact = calculateImpactFactor(system);

        // 组合风险评分（漏洞占70%，端口风险占30%）
        double riskScore = ((baseScore * 0.7) + (portRisk * 0.3)) * impact;

        // 限制评分范围在0.0-10.0之间
        riskScore = Math.min(10.0, Math.max(0.1, riskScore));

        // 生成修复建议
        List<String> recommendations = generateRecommendations(scanResult, system);

        return new RiskAssessment(
                riskScore,
                evaluateProtections(system.securityConfigs()),
                recommendations
        );
    }

    private double calculateBaseScore(ScanResult result) {
        // 处理空漏洞列表
        if (result.vulnerabilities().isEmpty()) {
            return 0.1; // 无漏洞时的基础评分
        }

        // 计算加权平均漏洞风险
        double totalWeight = 0.0;
        double weightedSum = 0.0;

        for (ScanResult.Vulnerability vuln : result.vulnerabilities()) {
            double severityWeight = getSeverityWeight(vuln.severity());
            double vulnWeight = severityWeight * getCriticalVulnWeight(vuln.cve());

            weightedSum += vulnWeight;
            totalWeight += 1.0;
        }

        return totalWeight > 0 ? weightedSum / totalWeight : 0.1;
    }

    private double getSeverityWeight(String severity) {
        if (severity == null) return 0.2;

        return switch(severity.toLowerCase()) {
            case "critical" -> 1.0;
            case "high" -> 0.8;
            case "medium" -> 0.5;
            case "low" -> 0.3;
            default -> 0.2;
        };
    }

    private double getCriticalVulnWeight(String cve) {
        // 检查是否为关键漏洞并应用权重
        for (Map.Entry<String, Double> entry : CRITICAL_VULN_WEIGHTS.entrySet()) {
            if (cve.contains(entry.getKey())) {
                return entry.getValue();
            }
        }
        return 1.0; // 默认权重
    }

    private double calculatePortRisk(List<ScanResult.PortInfo> ports) {
        if (ports.isEmpty()) {
            return 0.1; // 无开放端口时的最低风险
        }

        long highRiskCount = ports.stream()
                .filter(p -> HIGH_RISK_PORTS.contains(p.port()))
                .count();

        long mediumRiskCount = ports.stream()
                .filter(p -> MEDIUM_RISK_PORTS.contains(p.port()))
                .count();

        // 计算风险分数（每个高风险端口0.3分，每个中等风险端口0.1分）
        double portRisk = (highRiskCount * 0.3) + (mediumRiskCount * 0.1);

        // 限制最大风险分数为2.0
        return Math.min(2.0, portRisk);
    }

    private double calculateImpactFactor(NetworkSystem system) {
        double impactFactor = 1.0; // 默认影响因子

        Map<String, String> configs = system.securityConfigs();

        // 安全措施减少风险
        if (configs.containsKey("encryption")) impactFactor *= 0.7;
        if (configs.containsKey("firewall")) impactFactor *= 0.6;
        if (configs.containsKey("ids")) impactFactor *= 0.8;
        if (configs.containsKey("mfa")) impactFactor *= 0.9;

        // 安全措施缺失增加风险
        if (!configs.containsKey("patch-management")) impactFactor *= 1.2;
        if (!configs.containsKey("backup")) impactFactor *= 1.1;

        // 确保影响因子在0.3-1.5之间
        return Math.min(1.5, Math.max(0.3, impactFactor));
    }

    private List<String> generateRecommendations(ScanResult result, NetworkSystem system) {
        List<String> recommendations = new ArrayList<>();

        // 漏洞修复建议
        result.vulnerabilities().stream()
                .sorted(Comparator.comparing(ScanResult.Vulnerability::severity).reversed())
                .forEach(vuln -> {
                    recommendations.add("修复漏洞 " + vuln.cve() + " (" + vuln.severity() + "): " + vuln.description());
                });

        // 高风险端口建议
        result.openPorts().stream()
                .filter(p -> HIGH_RISK_PORTS.contains(p.port()))
                .forEach(port -> {
                    recommendations.add("关闭或保护高风险端口: " + port.port() + " (" + port.service() + ")");
                });

        // 安全配置建议
        Map<String, String> configs = system.securityConfigs();
        if (!configs.containsKey("firewall")) {
            recommendations.add("部署防火墙以控制网络流量");
        }
        if (!configs.containsKey("encryption")) {
            recommendations.add("实施数据传输加密机制");
        }
        if (!configs.containsKey("mfa")) {
            recommendations.add("启用多因素认证(MFA)增强账户安全");
        }

        // 添加通用建议
        recommendations.add("定期更新系统和应用程序补丁");
        recommendations.add("实施最小权限原则，限制用户和服务的访问权限");
        recommendations.add("定期备份关键数据并测试恢复流程");

        // 限制建议数量（最多10条）
        return recommendations.stream().limit(10).collect(Collectors.toList());
    }

    private String evaluateProtections(Map<String, String> configs) {
        int securityCounter = 0;

        // 检查关键安全措施
        if (configs.containsKey("firewall")) securityCounter++;
        if (configs.containsKey("encryption")) securityCounter++;
        if (configs.containsKey("ids")) securityCounter++;
        if (configs.containsKey("mfa")) securityCounter++;
        if (configs.containsKey("patch-management")) securityCounter++;

        // 评估防护等级
        return switch (securityCounter) {
            case 5 -> "Excellent";
            case 4 -> "Good";
            case 3 -> "Adequate";
            case 2 -> "Inadequate";
            default -> "Poor";
        };
    }
}