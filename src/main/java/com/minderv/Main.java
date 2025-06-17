package com.minderv;

import com.minderv.core.*;
import com.minderv.core.model.*;
import com.minderv.monitor.UpdateMonitor;
import com.minderv.scanners.VulnerabilityScanner;
import com.minderv.utils.ConfigLoader;
import com.minderv.utils.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class Main {
    private static final Logger logger = LogManager.getLogger(Main.class);
    private static UpdateMonitor monitor;

    public static void main(String[] args) {
        try {
            // 测试更新服务器连通性
            testUpdateServerConnection();

            // 初始化系统分析
            SystemAnalyzer analyzer = new SystemAnalyzer();
            NetworkSystem system = analyzer.analyzeSystem();

            // 生成评估计划
            AssessmentPlan plan = PlanGenerator.generatePlan(system);

            // 执行漏洞扫描
            VulnerabilityScanner scanner = new VulnerabilityScanner();
            ScanResult scanResult = scanner.performScan(system);

            // 导出扫描结果
            String exportPrefix = ConfigLoader.get("export.prefix", "minder_scan");
            FileUtils.exportScanResults(scanResult, exportPrefix);
            FileUtils.exportScanResultsToCSV(scanResult, exportPrefix);

            // 进行风险评估
            RiskAssessor assessor = new RiskAssessor();
            RiskAssessment assessment = assessor.assess(system, scanResult);

            // 生成报告
            ReportGenerator reporter = new ReportGenerator();
            reporter.generateReport(plan, scanResult, assessment);

            // 启动监控服务
            monitor = new UpdateMonitor();
            monitor.startMonitoring();

            // 注册关闭钩子
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                logger.info("正在关闭系统...");
                if (monitor != null) {
                    monitor.shutdown();
                }
            }));

        } catch (SecurityException e) {
            logger.error("安全违规: {}", e.getMessage());
            System.exit(1);
        } catch (Exception e) {
            logger.error("致命错误: {}", e.getMessage(), e);
            System.exit(2);
        }
    }

    private static void testUpdateServerConnection() {
        String url = ConfigLoader.get("update.url", "https://api.minderv.com/version");
        logger.info("测试更新服务器连通性: {}", url);

        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(5))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            logger.info("更新服务器测试成功，状态码: {}", response.statusCode());
        } catch (Exception e) {
            String errorMsg = "连接失败: ";
            if (e.getMessage() != null) {
                errorMsg += e.getMessage();
            } else {
                Throwable cause = e.getCause();
                if (cause != null) {
                    errorMsg += cause.getClass().getSimpleName();
                    if (cause.getMessage() != null) {
                        errorMsg += " (" + cause.getMessage() + ")";
                    }
                } else {
                    errorMsg += "无详细错误信息";
                }
            }
            logger.warn("更新服务器测试失败: {}", errorMsg);
        }
    }
}



