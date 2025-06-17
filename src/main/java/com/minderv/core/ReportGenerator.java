package com.minderv.core;

import com.minderv.core.model.*;
import com.minderv.utils.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ReportGenerator {
    private static final Logger logger = LogManager.getLogger(ReportGenerator.class);

    public void generateReport(AssessmentPlan plan, ScanResult result, RiskAssessment assessment) {
        Report report = new Report(
                "系统风险评分: " + assessment.riskScore(),
                result.vulnerabilities(),
                assessment.recommendations()
        );

        try {
            FileUtils.exportToWord(report);
            logger.info("报告生成成功");
        } catch (Exception e) {
            logger.error("报告生成失败: {}", e.getMessage());
        }
    }
}