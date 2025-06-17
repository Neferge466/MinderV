package com.minderv.scanners.impl;

import com.minderv.core.model.NetworkSystem;
import com.minderv.core.model.ScanResult;
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
import java.util.List;
import java.util.stream.Collectors;

public class NmapScanner {
    private static final Logger logger = LogManager.getLogger(NmapScanner.class);

    public static List<ScanResult.PortInfo> scanPorts(NetworkSystem system) {
        String target = validateTarget(system);
        String nmapPath = getValidatedNmapPath();

        try {
            Path tempFile = Files.createTempFile("nmap_scan", ".xml");

            // 构建命令列表（动态添加IPv6参数）
            List<String> command = new ArrayList<>();
            command.add(nmapPath);
            command.add("-sV");
            command.add("--script");
            command.add("vuln");

            // 如果目标是IPv6地址，添加-6参数
            if (target.contains(":")) {
                logger.info("添加IPv6扫描参数 (-6)");
                command.add("-6");
            }

            command.add("-oX");
            command.add(tempFile.toString());
            command.add(target);

            Process process = new ProcessBuilder(command).start();

            // 读取错误流以防止进程阻塞
            Thread errorThread = new Thread(() -> {
                try (BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                    String line;
                    while ((line = errorReader.readLine()) != null) {
                        logger.warn("Nmap 错误输出: {}", line);
                    }
                } catch (Exception e) {
                    logger.error("读取Nmap错误流失败", e);
                }
            });
            errorThread.start();

            int exitCode = process.waitFor();
            errorThread.join(); // 等待错误流读取完成

            if (exitCode != 0) {
                String error = "Nmap 退出代码: " + exitCode;
                logger.error("Nmap执行失败: {}", error);
                throw new RuntimeException("Nmap执行失败: " + error);
            }

            // 读取XML内容并记录用于调试
            String xmlContent = Files.readString(tempFile);
            logger.debug("Nmap XML 输出:\n{}", xmlContent);

            return parseXMLOutput(xmlContent);
        } catch (Exception e) {
            logger.error("扫描失败: {}", e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private static String validateTarget(NetworkSystem system) {
        logger.debug("可用网络接口: {}", system.interfaces().stream()
                .map(ni -> ni.name() + "=" + ni.address())
                .collect(Collectors.joining(", ")));

        // 优先选择IPv4地址
        for (NetworkSystem.NetworkInterface ni : system.interfaces()) {
            String addr = ni.address();
            if (addr != null && !addr.isEmpty() && addr.contains(".")) {
                logger.info("选择IPv4地址作为扫描目标: {}", addr);
                return addr;
            }
        }

        // 次优先选择IPv6地址（去除区域索引）
        for (NetworkSystem.NetworkInterface ni : system.interfaces()) {
            String addr = ni.address();
            if (addr != null && !addr.isEmpty() && addr.contains(":")) {
                // 移除IPv6地址的区域索引部分
                if (addr.contains("%")) {
                    addr = addr.substring(0, addr.indexOf('%'));
                }
                logger.info("选择IPv6地址作为扫描目标: {}", addr);
                return addr;
            }
        }

        // 回退到配置的备用地址
        String fallback = ConfigLoader.get("scan.fallback.target", "127.0.0.1");
        logger.warn("未找到有效地址，使用备用目标: {}", fallback);
        return fallback;
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

            if (result.getHost() == null) {
                logger.warn("XML中未找到主机信息");
                return List.of();
            }

            if (result.getHost().getPorts() == null) {
                logger.warn("XML中未找到端口信息");
                return List.of();
            }

            return result.getHost().getPorts().getPort().stream()
                    .filter(p -> p.getState() != null && "open".equals(p.getState().getState()))
                    .map(p -> {
                        // 安全处理每个字段
                        int port = safeParsePort(p.getPortid());
                        String service = (p.getService() != null && p.getService().getName() != null)
                                ? p.getService().getName()
                                : "unknown";

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

        public List<Port> getPort() { return port; }
        public void setPort(List<Port> port) { this.port = port; }
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