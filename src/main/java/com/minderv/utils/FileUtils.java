package com.minderv.utils;

import com.minderv.core.model.Report;
import com.minderv.core.model.ScanResult;
import org.apache.poi.xwpf.usermodel.*;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

public class FileUtils {
    public static void exportToWord(Report report) throws IOException {
        try (XWPFDocument doc = new XWPFDocument()) {
            // 标题
            XWPFParagraph title = doc.createParagraph();
            title.setAlignment(ParagraphAlignment.CENTER);
            XWPFRun titleRun = title.createRun();
            titleRun.setText("网络安全评估报告");
            titleRun.setBold(true);
            titleRun.setFontSize(16);

            // 内容
            addSection(doc, "漏洞发现", report.findings().toString());
            addSection(doc, "建议措施", String.join("\n", report.recommendations()));

            // 保存文件
            doc.write(new FileOutputStream("Assessment_Report.docx"));
        }
    }

    private static void addSection(XWPFDocument doc, String header, String content) {
        XWPFParagraph para = doc.createParagraph();
        XWPFRun run = para.createRun();
        run.setText(header + ":");
        run.setBold(true);
        run.addBreak();

        XWPFParagraph contentPara = doc.createParagraph();
        contentPara.createRun().setText(content);
    }

    /**
     * 导出扫描结果为文本文件
     * @param result 扫描结果
     * @param filePrefix 文件名前缀
     */
    public static void exportScanResults(ScanResult result, String filePrefix) {
        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        String filename = filePrefix + "_scan_results_" + timestamp + ".txt";

        try (PrintWriter writer = new PrintWriter(filename)) {
            // 写入端口扫描结果
            writer.println("===== 端口扫描结果 =====");
            writer.printf("%-8s %-8s %-20s%n", "端口", "状态", "服务");
            writer.println("----------------------------------");
            for (ScanResult.PortInfo port : result.openPorts()) {
                writer.printf("%-8d %-8s %-20s%n",
                        port.port(), port.state(), port.service());
            }
            writer.println();

            // 写入漏洞信息
            writer.println("===== 漏洞发现 =====");
            writer.printf("%-10s %-15s %-40s %-8s%n",
                    "服务", "CVE ID", "描述", "严重性");
            writer.println("----------------------------------------------------------------");
            for (ScanResult.Vulnerability vuln : result.vulnerabilities()) {
                writer.printf("%-10s %-15s %-40s %-8s%n",
                        vuln.service(), vuln.cve(),
                        truncate(vuln.description(), 40), vuln.severity());
            }

            writer.println("\n报告生成时间: " + new Date());
            writer.println("导出完成");

            System.out.println("扫描结果已导出到: " + filename);
        } catch (Exception e) {
            System.err.println("导出扫描结果失败: " + e.getMessage());
        }
    }

    private static String truncate(String text, int maxLength) {
        if (text.length() <= maxLength) return text;
        return text.substring(0, maxLength - 3) + "...";
    }

    /**
     * 导出扫描结果为 CSV 文件
     * @param result 扫描结果
     * @param filePrefix 文件名前缀
     */
    public static void exportScanResultsToCSV(ScanResult result, String filePrefix) {
        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        String filename = filePrefix + "_scan_results_" + timestamp + ".csv";

        try (PrintWriter writer = new PrintWriter(filename)) {
            // 写入 CSV 头部
            writer.println("端口,状态,服务,CVE ID,漏洞描述,严重性");

            // 组合端口和漏洞信息
            for (ScanResult.PortInfo port : result.openPorts()) {
                String portStr = String.valueOf(port.port());
                String service = port.service();

                // 查找此端口的漏洞
                List<ScanResult.Vulnerability> portVulns = result.vulnerabilities().stream()
                        .filter(v -> v.service().equalsIgnoreCase(service))
                        .toList();

                if (portVulns.isEmpty()) {
                    writer.println(portStr + "," + port.state() + "," + service + ",,,");
                } else {
                    for (ScanResult.Vulnerability vuln : portVulns) {
                        writer.println(String.format("%s,%s,%s,%s,%s,%s",
                                portStr, port.state(), service,
                                vuln.cve(), vuln.description(), vuln.severity()));
                    }
                }
            }

            System.out.println("CSV 扫描结果已导出到: " + filename);
        } catch (Exception e) {
            System.err.println("导出 CSV 扫描结果失败: " + e.getMessage());
        }
    }
}


