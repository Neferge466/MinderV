package com.minderv.scanners.impl;

import com.minderv.core.model.NetworkSystem;
import com.minderv.core.model.ScanResult;
import com.minderv.core.PlanGenerator;
import com.minderv.utils.ConfigLoader;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import jakarta.xml.bind.annotation.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class NmapScanner {
    private static final Logger logger = LogManager.getLogger(NmapScanner.class);
    // 扫描超时时间（分钟）
    private static final long SCAN_TIMEOUT_MINUTES = Long.parseLong(
            ConfigLoader.get("scan.timeout", "10")
    );

    public static List<ScanResult.PortInfo> scanPorts(NetworkSystem system) {
        String target = PlanGenerator.getScanTarget(system);
        String nmapPath = getValidatedNmapPath();

        try {
            Path tempFile = Files.createTempFile("nmap_scan", ".xml");

            // 构建命令列表
            List<String> command = new ArrayList<>();
            command.add(nmapPath);

            // 添加操作系统特定参数
            String os = System.getProperty("os.name", "").toLowerCase();
            if (os.contains("win")) {
                // 强制使用无特权模式
                command.add("--unprivileged");
                logger.info("Windows系统，强制使用无特权模式(--unprivileged)");
            }

            // ============== 优化参数 ==============
            // 核心扫描参数
            command.add("-sT");  // 使用TCP连接扫描
            logger.info("使用TCP连接扫描模式(-sT)");

            // 性能优化参数
            command.add("-Pn");  // 跳过主机发现
            command.add("-T5");  // 最激进的时序模板
            command.add("-n");   // 禁用DNS解析
            command.add("--max-rtt-timeout=500ms");
            command.add("--min-rtt-timeout=100ms");
            command.add("--initial-rtt-timeout=250ms");
            command.add("--max-retries=1");
            command.add("--min-rate=1000"); // 最小发包速率

            // 并行扫描参数
            command.add("--min-hostgroup=256");
            command.add("--min-parallelism=100");

            // 端口扫描策略
            if (target.contains("/") || target.contains("-")) {
                // 大范围扫描：只扫描最常见端口
                command.add("--top-ports=50"); // 只扫描前50个最常见端口
                logger.info("大范围扫描，启用常用端口扫描(--top-ports=50)");
            } else {
                // 单目标扫描：扫描所有端口
                command.add("-p-"); // 扫描所有端口
                logger.info("单目标扫描，启用全端口扫描(-p-)");
            }

            // 选择性启用服务检测
            boolean enableServiceDetection = Boolean.parseBoolean(
                    ConfigLoader.get("scan.service.enable", "true")
            );
            if (enableServiceDetection) {
                command.add("-sV"); // 服务版本检测
                command.add("--version-intensity=3"); // 中等强度检测
                logger.info("启用服务版本检测(-sV)");
            }

            // 选择性启用脚本扫描
            boolean enableScriptScan = Boolean.parseBoolean(
                    ConfigLoader.get("scan.script.enable", "false")
            );
            if (enableScriptScan) {
                command.add("--script");
                command.add("default,safe,vuln"); // 只运行安全脚本
                command.add("--script-timeout=30s"); // 脚本超时时间
                logger.info("启用脚本扫描(--script)");
            }
            // ============== 优化结束 ==============

            // 添加进度报告参数
            command.add("--stats-every=10s"); // 每10秒报告进度

            command.add("-oX");
            command.add(tempFile.toString());
            command.add(target);

            logger.info("执行 Nmap 命令: {}", String.join(" ", command));

            // 创建进程构建器
            ProcessBuilder processBuilder = new ProcessBuilder(command);

            // 重定向错误流到标准输出，避免阻塞
            processBuilder.redirectErrorStream(true);

            Process process = processBuilder.start();

            // 创建线程读取输出
            Thread outputReader = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        // 过滤并记录重要进度信息
                        if (line.contains("Stats:") || line.contains("Discovered") ||
                                line.contains("scan report") || line.contains("% done") ||
                                line.contains("ETC:")) {
                            logger.info("Nmap进度: {}", line);
                        }
                    }
                } catch (Exception e) {
                    logger.error("读取Nmap输出失败", e);
                }
            });
            outputReader.start();

            // 添加超时控制
            boolean finished = process.waitFor(SCAN_TIMEOUT_MINUTES, TimeUnit.MINUTES);

            if (!finished) {
                logger.error("Nmap扫描超时（{}分钟），终止进程...", SCAN_TIMEOUT_MINUTES);
                process.destroyForcibly();
                throw new RuntimeException("Nmap扫描超时");
            }

            int exitCode = process.exitValue();
            outputReader.join(); // 等待输出读取完成

            if (exitCode != 0) {
                String error = "Nmap 退出代码: " + exitCode;
                logger.error("Nmap执行失败: {}", error);

                // 添加扫描失败重试机制
                logger.warn("尝试简化扫描（仅端口扫描）...");
                return simplePortScan(target, nmapPath, tempFile);
            }

            // 读取XML内容并记录用于调试
            String xmlContent = Files.readString(tempFile);
            logger.debug("Nmap XML 输出:\n{}", xmlContent);

            return parseXMLOutput(xmlContent);
        } catch (Exception e) {
            logger.error("扫描失败: {}", e.getMessage(), e);
            throw new RuntimeException(e);
        }
    }

    // 简化扫描方法（仅基本端口扫描）
    private static List<ScanResult.PortInfo> simplePortScan(String target, String nmapPath, Path tempFile) {
        try {
            List<String> simpleCommand = new ArrayList<>();
            simpleCommand.add(nmapPath);

            if (System.getProperty("os.name", "").toLowerCase().contains("win")) {
                simpleCommand.add("--unprivileged");
            }

            simpleCommand.add("-sT");
            simpleCommand.add("-Pn"); // 跳过主机发现
            simpleCommand.add("-T5"); // 最快速扫描
            simpleCommand.add("-n");  // 禁用DNS解析

            // 快速扫描参数
            simpleCommand.add("--top-ports=100"); // 只扫描100个最常见端口
            simpleCommand.add("--open"); // 只显示开放端口

            simpleCommand.add("-oX");
            simpleCommand.add(tempFile.toString());
            simpleCommand.add(target);

            logger.info("执行简化扫描命令: {}", String.join(" ", simpleCommand));

            ProcessBuilder processBuilder = new ProcessBuilder(simpleCommand);
            processBuilder.redirectErrorStream(true);

            Process process = processBuilder.start();

            // 读取输出
            Thread outputReader = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (line.contains("Stats:") || line.contains("Discovered")) {
                            logger.info("Nmap进度: {}", line);
                        }
                    }
                } catch (Exception e) {
                    logger.error("读取Nmap输出失败", e);
                }
            });
            outputReader.start();

            boolean finished = process.waitFor(5, TimeUnit.MINUTES);

            if (!finished) {
                logger.error("简化扫描超时，终止进程...");
                process.destroyForcibly();
                throw new RuntimeException("简化扫描超时");
            }

            int exitCode = process.exitValue();
            outputReader.join();

            if (exitCode != 0) {
                throw new RuntimeException("简化扫描失败，退出码: " + exitCode);
            }

            String xmlContent = Files.readString(tempFile);
            return parseXMLOutput(xmlContent);
        } catch (Exception e) {
            logger.error("简化扫描失败: {}", e.getMessage());
            return List.of(); // 返回空结果
        }
    }

    private static String getValidatedNmapPath() {
        String path = ConfigLoader.get("nmap.path")
                .replace("/", System.getProperty("file.separator"))
                .replace("\\", System.getProperty("file.separator"));

        if (!Files.isExecutable(Paths.get(path))) {
            throw new SecurityException("Nmap路径不可执行: " + path);
        }
        return path;
    }

    private static List<ScanResult.PortInfo> parseXMLOutput(String xmlContent) {
        try {
            JAXBContext context = JAXBContext.newInstance(NmapRun.class);
            Unmarshaller unmarshaller = context.createUnmarshaller();
            StringReader reader = new StringReader(xmlContent);
            NmapRun result = (NmapRun) unmarshaller.unmarshal(reader);

            // 增强空指针检查
            if (result == null) {
                logger.error("XML解析结果为空");
                return List.of();
            }

            // 安全获取主机信息
            Host host = result.getHost();
            if (host == null) {
                logger.warn("XML中未找到主机信息");
                return List.of();
            }

            // 安全获取端口信息
            Ports ports = host.getPorts();
            if (ports == null) {
                logger.info("没有找到任何端口信息");
                return List.of();
            }

            // 安全获取端口列表
            List<Port> portList = Optional.ofNullable(ports.getPort())
                    .orElseGet(Collections::emptyList);

            return portList.stream()
                    .filter(p -> p != null && p.getState() != null && "open".equals(p.getState().getState()))
                    .map(p -> {
                        // 安全处理每个字段
                        int port = safeParsePort(p.getPortid());
                        String service = "unknown";

                        if (p.getService() != null) {
                            service = Optional.ofNullable(p.getService().getName())
                                    .orElse("unknown");
                        }

                        return new ScanResult.PortInfo(
                                port,
                                p.getState().getState(),
                                service
                        );
                    })
                    .filter(p -> p.port() > 0) // 过滤无效端口
                    .toList();
        } catch (JAXBException e) {
            // 记录部分XML内容用于调试
            String sample = xmlContent.length() > 500 ? xmlContent.substring(0, 500) + "..." : xmlContent;
            logger.error("XML解析失败，错误: {}，XML样本:\n{}", e.getMessage(), sample);
            throw new RuntimeException("XML解析失败: " + e.getLinkedException().getMessage(), e);
        } catch (Exception e) {
            logger.error("XML处理错误: {}", e.getMessage());
            throw new RuntimeException("XML处理错误: " + e.getMessage(), e);
        }
    }

    private static int safeParsePort(String portid) {
        try {
            return Integer.parseInt(portid);
        } catch (NumberFormatException e) {
            logger.warn("无效的端口号: {}", portid);
            return -1;
        }
    }

    @XmlRootElement(name = "nmaprun")
    @XmlAccessorType(XmlAccessType.FIELD)
    public static class NmapRun {
        @XmlElement(name = "host")
        private Host host;

        public Host getHost() { return host; }
        public void setHost(Host host) { this.host = host; }
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class Host {
        @XmlElement(name = "ports")
        private Ports ports;

        public Ports getPorts() { return ports; }
        public void setPorts(Ports ports) { this.ports = ports; }
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class Ports {
        @XmlElement(name = "port")
        private List<Port> port;

        public List<Port> getPort() {
            return port != null ? port : Collections.emptyList();
        }
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class Port {
        @XmlAttribute(name = "portid")
        private String portid;

        @XmlElement(name = "state")
        private State state;

        @XmlElement(name = "service")
        private Service service;

        public String getPortid() { return portid; }
        public State getState() { return state; }
        public Service getService() { return service; }
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class State {
        @XmlAttribute(name = "state")
        private String state;

        public String getState() { return state; }
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class Service {
        @XmlAttribute(name = "name")
        private String name;

        public String getName() { return name; }
    }
}