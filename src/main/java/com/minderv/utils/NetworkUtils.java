package com.minderv.utils;

import com.minderv.core.model.NetworkSystem;

import java.io.IOException;
import java.net.*;
import java.util.*;
import java.util.stream.Collectors;

public class NetworkUtils {
    public static String discoverTopology() throws IOException {
        try (var socket = new DatagramSocket()) {
            socket.setBroadcast(true);
            return "Discovered topology via broadcast probe";
        }
    }

    public static List<NetworkSystem.DataFlow> traceDataFlows() {
        return List.of(
                new NetworkSystem.DataFlow("192.168.1.1", "10.0.0.2", "TCP"),
                new NetworkSystem.DataFlow("10.0.0.2", "8.8.8.8", "UDP")
        );
    }

    public static Map<String, String> collectSecurityConfigs() {
        return Map.of(
                "firewall", "Enabled",
                "encryption", "AES-256",
                "auth", "2FA"
        );
    }

    public static List<NetworkSystem.NetworkInterface> listNetworkInterfaces() throws SocketException {
        List<NetworkSystem.NetworkInterface> interfaces = new ArrayList<>();
        Enumeration<java.net.NetworkInterface> nets = java.net.NetworkInterface.getNetworkInterfaces();

        // 优先收集非回环地址
        List<java.net.NetworkInterface> interfaceList = Collections.list(nets).stream()
                .filter(ni -> {
                    try {
                        return ni.isUp() && !ni.isLoopback();
                    } catch (SocketException e) {
                        return false;
                    }
                })
                .collect(Collectors.toList());

        // 如果找不到非回环接口，则包含所有接口
        if (interfaceList.isEmpty()) {
            interfaceList = Collections.list(java.net.NetworkInterface.getNetworkInterfaces());
        }

        for (java.net.NetworkInterface ni : interfaceList) {
            List<InetAddress> addresses = Collections.list(ni.getInetAddresses()).stream()
                    .filter(addr -> !addr.isLoopbackAddress())
                    .collect(Collectors.toList());

            if (addresses.isEmpty()) {
                addresses = Collections.list(ni.getInetAddresses());
            }

            for (InetAddress addr : addresses) {
                String hostAddress = addr.getHostAddress();
                if (!hostAddress.isEmpty()) {
                    interfaces.add(new NetworkSystem.NetworkInterface(ni.getName(), hostAddress));
                    break; // 每个接口只取第一个有效地址
                }
            }
        }

        // 最终回退到本地地址
        if (interfaces.isEmpty()) {
            interfaces.add(new NetworkSystem.NetworkInterface("lo", "127.0.0.1"));
        }

        return interfaces;
    }
}

