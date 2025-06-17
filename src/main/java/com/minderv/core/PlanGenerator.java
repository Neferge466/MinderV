package com.minderv.core;

import com.minderv.core.model.AssessmentPlan;
import com.minderv.core.model.NetworkSystem;
import com.minderv.utils.ConfigLoader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.stream.Collectors;

public class PlanGenerator {
    private static final Logger logger = LogManager.getLogger(PlanGenerator.class);

    public static AssessmentPlan generatePlan(NetworkSystem system) {
        LocalDateTime start = LocalDateTime.now();
        LocalDateTime end = start.plus(Duration.ofHours(2));

        List<String> methods = List.of("端口扫描", "漏洞验证", "配置审计");
        List<String> resources = List.of(
                ConfigLoader.get("nmap.path"),
                "漏洞数据库",
                "网络嗅探器"
        );

        // 获取扫描目标
        String target = getScanTarget(system);

        AssessmentPlan plan = new AssessmentPlan(
                target,
                start,
                end,
                methods,
                resources
        );

        logger.info("生成评估计划: {}", plan);
        return plan;
    }

    public static String getScanTarget(NetworkSystem system) {
        // 1. 检查命令行参数 (最高优先级)
        String cmdTarget = System.getProperty("scan.target");
        if (cmdTarget != null && !cmdTarget.isBlank()) {
            logger.info("使用命令行指定的扫描目标: {}", cmdTarget);
            return cmdTarget;
        }

        // 2. 检查 IP 范围配置
        String ipRange = ConfigLoader.get("scan.range", "");
        if (!ipRange.isBlank()) {
            logger.info("使用 IP 范围扫描目标: {}", ipRange);
            return ipRange;
        }

        // 3. 检查配置文件中的目标
        String scanMode = ConfigLoader.get("scan.mode", "single");
        List<String> targets = new ArrayList<>();

        // 添加 IP 目标
        String ips = ConfigLoader.get("scan.target.ips", "");
        if (!ips.isBlank()) {
            targets.addAll(Arrays.asList(ips.split(",")));
        }

        // 添加域名目标
        String domains = ConfigLoader.get("scan.target.domains", "");
        if (!domains.isBlank()) {
            targets.addAll(Arrays.asList(domains.split(",")));
        }

        // 应用排除列表
        String exclude = ConfigLoader.get("scan.exclude", "");
        if (!exclude.isBlank()) {
            List<String> excludeList = Arrays.asList(exclude.split(","));
            targets = targets.stream()
                    .filter(t -> !excludeList.contains(t))
                    .collect(Collectors.toList());
            logger.info("应用排除列表后目标: {}", targets);
        }

        // 多目标模式
        if ("multi".equalsIgnoreCase(scanMode) && !targets.isEmpty()) {
            String joinedTargets = String.join(",", targets);
            logger.info("使用多目标扫描: {}", joinedTargets);
            return joinedTargets;
        }

        // 单目标模式 (返回第一个目标)
        if (!targets.isEmpty()) {
            logger.info("使用配置中的扫描目标: {}", targets.get(0));
            return targets.get(0);
        }

        // 4. 默认行为 (自动选择目标)
        return system.interfaces().stream()
                .map(NetworkSystem.NetworkInterface::address)
                .filter(addr -> !addr.isEmpty())
                .findFirst()
                .orElseThrow(() -> {
                    String errorMsg = "未找到有效的网络接口地址，可用接口: " +
                            system.interfaces().stream()
                                    .map(ni -> ni.name() + "(" + ni.address() + ")")
                                    .toList();
                    logger.error(errorMsg);
                    return new NoSuchElementException(errorMsg);
                });
    }
}

