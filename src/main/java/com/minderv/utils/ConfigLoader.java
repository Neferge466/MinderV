package com.minderv.utils;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ConfigLoader {
    private static final Logger logger = LogManager.getLogger(ConfigLoader.class);
    private static final Properties config = new Properties();

    static {
        try (InputStream input = ConfigLoader.class
                .getResourceAsStream("/config.properties")) {
            config.load(input);
            validateCriticalConfig();
        } catch (Exception e) {
            throw new RuntimeException("配置加载失败: " + e.getMessage());
        }
    }

    private static void validateCriticalConfig() {
        validateNmapPath();
        validateSSLConfig();
    }

    private static void validateNmapPath() {
        String path = get("nmap.path")
                .replace("/", System.getProperty("file.separator"))
                .replace("\\", System.getProperty("file.separator"));

        if (!Files.isExecutable(Paths.get(path))) {
            throw new RuntimeException("Nmap路径无效或不可执行: " + path);
        }
    }

    private static void validateSSLConfig() {
        if ("true".equalsIgnoreCase(get("ssl.verify"))) {
            Path keystore = Paths.get(get("ssl.keystore.path"));
            if (!Files.exists(keystore)) {
                throw new RuntimeException("SSL证书库不存在: " + keystore);
            }
        }
    }

    public static String get(String key) {
        String value = config.getProperty(key);
        if (value == null) {
            throw new IllegalArgumentException("缺少必要配置项: " + key);
        }
        return value;
    }

    // 新增带默认值的获取方法
    public static String get(String key, String defaultValue) {
        String value = config.getProperty(key);
        if (value == null || value.isBlank()) {
            logger.warn("配置项 {} 未找到，使用默认值: {}", key, defaultValue);
            return defaultValue;
        }
        return value;
    }
}