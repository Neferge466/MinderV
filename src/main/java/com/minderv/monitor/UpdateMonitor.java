package com.minderv.monitor;

import com.minderv.utils.ConfigLoader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.concurrent.*;

public class UpdateMonitor {
    private static final Logger logger = LogManager.getLogger(UpdateMonitor.class);
    private HttpClient client;
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);

    public UpdateMonitor() {
        initHttpClient();
    }

    private void initHttpClient() {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
            if ("true".equalsIgnoreCase(ConfigLoader.get("ssl.verify"))) {
                sslContext.init(null, null, null);
            } else {
                sslContext.init(null, getTrustAllCerts(), new SecureRandom());
            }

            HttpClient.Builder builder = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(15))
                    .sslContext(sslContext);

            if (Boolean.parseBoolean(ConfigLoader.get("proxy.enabled", "false"))) {
                String proxyHost = ConfigLoader.get("proxy.host", "");
                int proxyPort = Integer.parseInt(ConfigLoader.get("proxy.port", "8080"));
                builder.proxy(ProxySelector.of(new InetSocketAddress(proxyHost, proxyPort)));
            }

            this.client = builder.build();
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException("HTTP客户端初始化失败", e);
        }
    }

    private TrustManager[] getTrustAllCerts() {
        return new TrustManager[]{
                new X509TrustManager() {
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                }
        };
    }

    public void startMonitoring() {
        if (validateUpdateConfig()) {
            long interval = Long.parseLong(ConfigLoader.get("update.interval", "7"));
            scheduler.scheduleAtFixedRate(this::checkUpdates, 0, interval, TimeUnit.DAYS);
        }
    }

    private boolean validateUpdateConfig() {
        try {
            String url = ConfigLoader.get("update.url");
            URI.create(url);
            logger.info("更新URL验证成功: {}", url);
            return true;
        } catch (Exception e) {
            logger.error("更新配置验证失败: {}", e.getMessage());
            return false;
        }
    }

    private void checkUpdates() {
        int retryCount = Integer.parseInt(ConfigLoader.get("update.retry.count", "3"));
        int retryDelay = Integer.parseInt(ConfigLoader.get("update.retry.delay", "5"));

        for (int attempt = 1; attempt <= retryCount; attempt++) {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(ConfigLoader.get("update.url")))
                        .timeout(Duration.ofSeconds(
                                Integer.parseInt(ConfigLoader.get("update.timeout", "15"))
                        ))
                        .header("User-Agent", "MinderV/1.0")
                        .GET()
                        .build();

                HttpResponse<String> response = client.send(
                        request, HttpResponse.BodyHandlers.ofString()
                );

                if (response.statusCode() == 200) {
                    logger.info("更新检查成功 (尝试 {}/{})", attempt, retryCount);
                    processResponse(response.body());
                    return;
                } else {
                    logger.warn("更新检查失败，状态码: {} (尝试 {}/{})",
                            response.statusCode(), attempt, retryCount);
                }
            } catch (Exception e) {
                logger.error("更新检查异常 (尝试 {}/{}): {}",
                        attempt, retryCount, e.getMessage());
            }

            // 重试前等待（最后一次不等待）
            if (attempt < retryCount) {
                try {
                    Thread.sleep(retryDelay * 1000L);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }

        logger.error("更新检查失败，已达最大重试次数: {}", retryCount);
    }

    private void processResponse(String body) {
        // 实现实际的版本解析逻辑
        logger.info("收到更新响应: {}", body);
        // 这里添加版本比较和更新提示逻辑
    }

    public void shutdown() {
        try {
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}