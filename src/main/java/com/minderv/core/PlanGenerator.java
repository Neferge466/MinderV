package com.minderv.core;

import com.minderv.core.model.AssessmentPlan;
import com.minderv.core.model.NetworkSystem;
import com.minderv.utils.ConfigLoader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.NoSuchElementException;

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

        String target = system.interfaces().stream()
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
}