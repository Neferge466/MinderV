package com.minderv.core;

import com.minderv.core.model.NetworkSystem;
import com.minderv.utils.NetworkUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;

public class SystemAnalyzer {
    private static final Logger logger = LogManager.getLogger(SystemAnalyzer.class);

    public NetworkSystem analyzeSystem() throws SecurityException {
        try {
            return new NetworkSystem(
                    NetworkUtils.discoverTopology(),
                    NetworkUtils.traceDataFlows(),
                    NetworkUtils.collectSecurityConfigs(),
                    NetworkUtils.listNetworkInterfaces()
            );
        } catch (IOException e) {
            logger.error("Network analysis failed: {}", e.getMessage());
            throw new SecurityException("Network analysis failure", e);
        }
    }
}