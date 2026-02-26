package alvr.client;

import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.BatteryManager;
import android.os.Build;
import android.os.PowerManager;
import android.os.SystemClock;
import android.util.Log;

import com.google.gson.Gson;
import com.htc.customizedlib.CSWifiManager;
import com.htc.customizedlib.CustomizedService;
import com.htc.customizedlib.FotaManager;
import com.htc.customizedlib.IPDManager;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public final class DiagnosticManager {
    private static final String TAG = "DiagnosticManager";
    private static final int UDP_PORT = 9123;
    private static final int HTTP_PORT = 9124;

    private static final int DEFAULT_DURATION_MS = 10_000;
    private static final int DEFAULT_RATE_HZ = 50;
    private static final int DEFAULT_PAYLOAD_BYTES = 64;
    private static final double DEFAULT_TARGET_MBPS = 45.0;
    private static final int DEFAULT_EXPECTED_PACKETS = -1;

    private static final Object LOCK = new Object();
    private static final Gson GSON = new Gson();

    private static Context appContext;
    private static Thread serverThread;
    private static ServerSocket serverSocket;
    private static Thread worker;
    private static Thread wifiReconnectThread;
    private static volatile boolean running = false;
    private static volatile boolean wifiReconnectRunning = false;
    private static volatile String lastResultJson =
            "{ \"status\": \"IDLE\", \"message\": \"No tests run yet\" }";
    private static volatile String lastCpuScope = "unknown";
    private static ExecutorService clientExecutor = Executors.newCachedThreadPool();

    private DiagnosticManager() {
    }

    public static void start(Context context) {
        synchronized (LOCK) {
            if (serverThread != null) {
                return;
            }
            appContext = context.getApplicationContext();
            try {
                CustomizedService.init(appContext, new com.htc.customizedlib.CustomizedService.InitListener() {
                    @Override
                    public void onConnected() {
                        Log.i(TAG, "CustomizedService connected");
                    }

                    @Override
                    public void onDisconnected() {
                        Log.w(TAG, "CustomizedService disconnected");
                    }
                });
            } catch (Throwable t) {
                Log.w(TAG, "CustomizedService init failed: " + t.getMessage());
            }
            startHttpServer();
            startWifiReconnectLoop();
        }
    }


    public static void stop() {
        synchronized (LOCK) {
            stopHttpServer();
            stopTest();
            stopWifiReconnectLoop();
            appContext = null;
        }
    }

    private static void startHttpServer() {
        if (clientExecutor == null || clientExecutor.isShutdown()) {
            clientExecutor = Executors.newCachedThreadPool();
        }
        serverThread = new Thread(() -> {
            try {
                serverSocket = new ServerSocket(HTTP_PORT);
                while (!Thread.currentThread().isInterrupted()) {
                    Socket client = serverSocket.accept();
                    clientExecutor.execute(() -> handleClient(client));
                }
            } catch (Throwable t) {
                Log.w(TAG, "HTTP server stopped: " + t.getMessage());
            } finally {
                try {
                    if (serverSocket != null) {
                        serverSocket.close();
                    }
                } catch (Throwable ignored) {
                }
                serverSocket = null;
            }
        }, "DiagnosticHttp");
        serverThread.start();
    }

    private static void stopHttpServer() {
        if (clientExecutor != null) {
            clientExecutor.shutdownNow();
        }
        if (serverThread != null) {
            serverThread.interrupt();
            serverThread = null;
        }
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (Throwable ignored) {
            }
            serverSocket = null;
        }
    }

    private static void startWifiReconnectLoop() {
        if (wifiReconnectThread != null) {
            return;
        }
        wifiReconnectRunning = true;
        wifiReconnectThread = new Thread(() -> {
            while (wifiReconnectRunning && !Thread.currentThread().isInterrupted()) {
                try {
                    boolean connected = isWifiConnected();
                    if (connected) {
                        Thread.sleep(10_000);
                    } else {
                        reconnectWifi();
                        Thread.sleep(1_000);
                    }
                } catch (InterruptedException ignored) {
                    break;
                } catch (Throwable t) {
                    Log.w(TAG, "WiFi reconnect loop error: " + t.getMessage());
                }
            }
        }, "WifiReconnectLoop");
        wifiReconnectThread.start();
    }

    private static void stopWifiReconnectLoop() {
        wifiReconnectRunning = false;
        if (wifiReconnectThread != null) {
            wifiReconnectThread.interrupt();
            wifiReconnectThread = null;
        }
    }

    private static void handleClient(Socket socket) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String line = reader.readLine();
            if (line == null) {
                return;
            }

            if (line.startsWith("GET /start-test")) {
                NetworkTestConfig config = parseStartRequest(line);
                if (config == null) {
                    sendResponse(socket, "400 Bad Request", "Invalid request", "text/plain");
                    return;
                }
                if (config.requiresTarget() && (config.targetHost == null || config.targetHost.isEmpty())) {
                    sendResponse(socket, "400 Bad Request", "Missing target query param", "text/plain");
                    return;
                }
                if (!running) {
                    startTest(config);
                    sendResponse(socket, "200 OK", "Test Started", "text/plain");
                } else {
                    sendResponse(socket, "409 Conflict", "Test already running", "text/plain");
                }
            } else if (line.startsWith("GET /get-results")) {
                sendResponse(socket, "200 OK", lastResultJson, "application/json");
            } else if (line.startsWith("GET /get-hardware-stats")) {
                sendResponse(socket, "200 OK", getHardwareStatsJson(), "application/json");
            } else if (line.startsWith("GET /get-wifi-stats")) {
                sendResponse(socket, "200 OK", getWifiStatsJson(), "application/json");
            } else if (line.startsWith("GET /scan-wifi")) {
                sendResponse(socket, "200 OK", scanWifiJson(), "application/json");
            } else if (line.startsWith("GET /stop-test")) {
                stopTest();
                sendResponse(socket, "200 OK", "Test Stopped", "text/plain");
            } else if (line.startsWith("GET /reboot")) {
                try {
                    if (!isCustomizedReady()) {
                        sendResponse(socket, "503 Service Unavailable",
                                "CustomizedService not connected", "text/plain");
                        return;
                    }
                    CustomizedService.rebootHMD();
                    sendResponse(socket, "200 OK", "Rebooting", "text/plain");
                } catch (Throwable t) {
                    String msg = t.getMessage() != null ? t.getMessage() : t.getClass().getSimpleName();
                    sendResponse(socket, "500 Internal Server Error", "Reboot failed: " + msg, "text/plain");
                }
            } else if (line.startsWith("GET /battery")) {
                sendResponse(socket, "200 OK", getBatteryInfoJson(), "application/json");
            } else if (line.startsWith("GET /check-firmware")) {
                sendResponse(socket, "200 OK", getFirmwareInfoJson(), "application/json");
            } else if (line.startsWith("GET /forget-wifi")) {
                sendResponse(socket, "200 OK", forgetWifiJson(line), "application/json");
            } else if (line.startsWith("GET /ipd/get")) {
                sendResponse(socket, "200 OK", getIpdJson(), "application/json");
            } else if (line.startsWith("GET /ipd/set")) {
                sendResponse(socket, "200 OK", setIpdJson(line), "application/json");
            } else if (line.startsWith("GET /ipd/auto")) {
                sendResponse(socket, "200 OK", triggerAutoIpdJson(false), "application/json");
            } else if (line.startsWith("GET /ipd/auto-ui")) {
                sendResponse(socket, "200 OK", triggerAutoIpdJson(true), "application/json");
            } else if (line.startsWith("GET /ipd/auto-info")) {
                sendResponse(socket, "200 OK", getAutoIpdInfoJson(), "application/json");
            } else if (line.startsWith("GET /customized-status")) {
                sendResponse(socket, "200 OK", getCustomizedStatusJson(), "application/json");
            } else if (line.startsWith("GET /query-wifi-status-raw")) {
                sendResponse(socket, "200 OK", getWifiStatusRawJson(), "application/json");
            } else if (line.startsWith("GET /shutdown-app")) {
                sendResponse(socket, "200 OK", "Shutting down app", "text/plain");
                scheduleProcessShutdown();
            } else {
                sendResponse(socket, "404 Not Found",
                        "Endpoints: /start-test, /stop-test, /get-results, /get-hardware-stats, /get-wifi-stats, /scan-wifi, /reboot, /battery, /check-firmware, /forget-wifi, /ipd/get, /ipd/set, /ipd/auto, /ipd/auto-ui, /ipd/auto-info, /customized-status, /query-wifi-status-raw, /shutdown-app",
                        "text/plain");
            }
        } catch (Throwable t) {
            Log.w(TAG, "Client handler error: " + t.getMessage());
        } finally {
            try {
                socket.close();
            } catch (Throwable ignored) {
            }
        }
    }

    private static void reconnectWifi() {
        if (appContext == null || !isCustomizedReady()) {
            return;
        }
        SavedWifi saved = getSingleSavedWifi();
        if (saved == null) {
            return;
        }

        CSWifiManager.NetworkIdParamsOrResult params = new CSWifiManager.NetworkIdParamsOrResult();
        params.networkId = saved.networkId;

        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<String> errorRef = new AtomicReference<>(null);

        CSWifiManager.connectWifi(params, new com.htc.customizedlib.CustomizedService.OperationListener() {
            @Override
            public void onSuccess(String result) {
                latch.countDown();
            }

            @Override
            public void onFail(int code, String message) {
                errorRef.set("code=" + code + ", message=" + jsonEscape(message));
                latch.countDown();
            }
        });

        try {
            latch.await(3, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
        }

        String err = errorRef.get();
        if (err != null) {
            Log.w(TAG, "WiFi reconnect result: " + err);
        }
    }

    private static boolean isWifiConnected() {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<String> statusRef = new AtomicReference<>(null);
        AtomicReference<String> statusErr = new AtomicReference<>(null);

        CSWifiManager.queryWifiStatus(new com.htc.customizedlib.CustomizedService.OperationListener() {
            @Override
            public void onSuccess(String result) {
                statusRef.set(result);
                latch.countDown();
            }

            @Override
            public void onFail(int code, String message) {
                statusErr.set("code=" + code + ", message=" + jsonEscape(message));
                latch.countDown();
            }
        });

        try {
            latch.await(3, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
        }

        String raw = statusRef.get();
        if (raw == null) {
            String err = statusErr.get();
            if (err != null) {
                Log.w(TAG, "WiFi status error: " + err);
            }
            return false;
        }

        try {
            CSWifiManager.WifiStatusResult status =
                    GSON.fromJson(raw, CSWifiManager.WifiStatusResult.class);
            if (status == null || status.wifiConnectionState == null) {
                return false;
            }
            String state = status.wifiConnectionState.toString();
            return "CONNECTED".equalsIgnoreCase(state) || "COMPLETED".equalsIgnoreCase(state);
        } catch (Throwable t) {
            Log.w(TAG, "WiFi status parse error: " + t.getMessage());
            return false;
        }
    }

    private static final class SavedWifi {
        final int networkId;
        final String ssid;

        SavedWifi(int networkId, String ssid) {
            this.networkId = networkId;
            this.ssid = ssid != null ? ssid : "";
        }
    }

    private static SavedWifi getSingleSavedWifi() {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<String> savedRef = new AtomicReference<>(null);
        AtomicReference<String> savedErr = new AtomicReference<>(null);

        CSWifiManager.getSavedWifiConfigList(new com.htc.customizedlib.CustomizedService.OperationListener() {
            @Override
            public void onSuccess(String result) {
                savedRef.set(result);
                latch.countDown();
            }

            @Override
            public void onFail(int code, String message) {
                savedErr.set("code=" + code + ", message=" + jsonEscape(message));
                latch.countDown();
            }
        });

        try {
            latch.await(3, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
        }

        String raw = savedRef.get();
        if (raw == null) {
            String err = savedErr.get();
            if (err != null) {
                Log.w(TAG, "WiFi reconnect saved list error: " + err);
            }
            return null;
        }

        try {
            CSWifiManager.CSWifiConfigList list =
                    GSON.fromJson(raw, CSWifiManager.CSWifiConfigList.class);
            if (list == null || list.CSWifiConfigs == null) {
                return null;
            }
            if (list.CSWifiConfigs.size() != 1) {
                return null;
            }
            com.htc.customizedlib.CSWifiConfig cfg = list.CSWifiConfigs.get(0);
            return new SavedWifi(cfg.networkId, cfg.ssid);
        } catch (Throwable t) {
            Log.w(TAG, "WiFi reconnect parse error: " + t.getMessage());
            return null;
        }
    }

    private static void sendResponse(Socket socket, String status, String body, String contentType) {
        try {
            byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
            String header = "HTTP/1.1 " + status + "\r\n" +
                    "Content-Type: " + contentType + "\r\n" +
                    "Content-Length: " + bodyBytes.length + "\r\n" +
                    "Access-Control-Allow-Origin: *\r\n\r\n";
            OutputStream out = socket.getOutputStream();
            out.write(header.getBytes(StandardCharsets.UTF_8));
            out.write(bodyBytes);
            out.flush();
        } catch (Throwable t) {
            Log.w(TAG, "Response error: " + t.getMessage());
        }
    }


    private static NetworkTestConfig parseStartRequest(String line) {
        int pathStart = line.indexOf(' ');
        int pathEnd = line.indexOf(' ', pathStart + 1);
        if (pathStart == -1 || pathEnd == -1) {
            return null;
        }
        String path = line.substring(pathStart + 1, pathEnd);
        Map<String, String> queryParams = new HashMap<>();
        int q = path.indexOf('?');
        if (q != -1) {
            parseQuery(path.substring(q + 1), queryParams);
        }

        NetworkTestConfig cfg = new NetworkTestConfig();
        cfg.targetHost = getQueryParam(queryParams, "target");
        cfg.mode = getQueryParam(queryParams, "mode");
        cfg.targetPort = getQueryInt(queryParams, "port", UDP_PORT);
        cfg.durationMs = getQueryInt(queryParams, "duration_ms", DEFAULT_DURATION_MS);
        cfg.rateHz = getQueryInt(queryParams, "rate_hz", DEFAULT_RATE_HZ);
        cfg.payloadBytes = getQueryInt(queryParams, "payload_bytes", DEFAULT_PAYLOAD_BYTES);
        cfg.targetMbps = getQueryDouble(queryParams, "target_mbps", DEFAULT_TARGET_MBPS);
        cfg.expectedPackets = getQueryInt(queryParams, "expected_packets", DEFAULT_EXPECTED_PACKETS);
        return cfg;
    }

    private static void parseQuery(String query, Map<String, String> params) {
        if (query == null || query.isEmpty()) {
            return;
        }
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            if (eq == -1) {
                continue;
            }
            params.put(pair.substring(0, eq), pair.substring(eq + 1));
        }
    }

    private static String getQueryParam(Map<String, String> params, String key) {
        return params.get(key);
    }

    private static int getQueryInt(Map<String, String> params, String key, int fallback) {
        String v = getQueryParam(params, key);
        if (v == null || v.isEmpty()) {
            return fallback;
        }
        try {
            return Integer.parseInt(v);
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static double getQueryDouble(Map<String, String> params, String key, double fallback) {
        String v = getQueryParam(params, key);
        if (v == null || v.isEmpty()) {
            return fallback;
        }
        try {
            return Double.parseDouble(v);
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static void startTest(NetworkTestConfig config) {
        if (running) {
            return;
        }
        running = true;
        lastResultJson = "{ \"status\": \"RUNNING\", \"message\": \"Test in progress...\", \"timestamp\": " +
                System.currentTimeMillis() + " }";

        worker = new Thread(() -> {
            try {
                runTest(config);
            } catch (Throwable t) {
                String msg = "Exception: " + (t.getMessage() != null ? t.getMessage() : t.getClass().getSimpleName());
                lastResultJson = "{ \"status\": \"ERROR\", \"message\": \"" + msg + "\", \"timestamp\": " +
                        System.currentTimeMillis() + " }";
            } finally {
                running = false;
            }
        }, "DiagnosticWorker");
        worker.start();
    }

    private static void stopTest() {
        running = false;
        if (worker != null) {
            try {
                worker.join(500);
            } catch (InterruptedException ignored) {
            }
            worker = null;
        }
    }

    private static class HardwareStatsResponse {
        String status = "OK";
        long timestamp;
        double cpu_percent;
        String cpu_scope;
        long mem_total_bytes;
        long mem_available_bytes;
        long mem_used_bytes;
        int battery_percent;
        boolean battery_charging;
        double battery_temp_c;
        int thermal_status;
        int proc_pss_kb;
        long[] cpu_freqs_hz;
        long uptime_ms;
    }

    private static String getHardwareStatsJson() {
        HardwareStatsResponse response = new HardwareStatsResponse();
        response.timestamp = System.currentTimeMillis();
        response.cpu_percent = readCpuUsagePercent();
        response.cpu_scope = lastCpuScope;
        MemoryStats mem = readMemoryStats();
        response.mem_total_bytes = mem.totalBytes;
        response.mem_available_bytes = mem.availableBytes;
        response.mem_used_bytes = mem.usedBytes;
        BatteryStats battery = readBatteryStats();
        response.battery_percent = battery.percent;
        response.battery_charging = battery.charging;
        response.battery_temp_c = battery.tempC;
        ThermalStats thermal = readThermalStats();
        response.thermal_status = thermal.status;
        ProcessMemoryStats procMem = readProcessMemoryStats();
        response.proc_pss_kb = procMem.totalPssKb;
        response.cpu_freqs_hz = readCpuFreqStats();
        response.uptime_ms = SystemClock.elapsedRealtime();
        return GSON.toJson(response);
    }

    private static String getWifiStatsJson() {
        long now = System.currentTimeMillis();
        WifiStats wifi = readWifiStats();
        int freqMhz = wifi.frequencyMhz;
        String band;
        if (CSWifiManager.is24GHz(freqMhz)) {
            band = "2.4ghz";
        } else if (CSWifiManager.is5GHz(freqMhz)) {
            band = "5ghz";
        } else if (CSWifiManager.is6GHz(freqMhz)) {
            band = "6ghz";
        } else {
            band = "unknown";
        }

        boolean customConnected = isCustomizedReady();
        String customStatusOut = "{\"error\":\"not connected\"}";
        String customSavedOut = "{\"error\":\"not connected\"}";
        if (customConnected) {
            CountDownLatch latch = new CountDownLatch(2);
            AtomicReference<String> statusRef = new AtomicReference<>(null);
            AtomicReference<String> savedRef = new AtomicReference<>(null);
            AtomicReference<String> statusErr = new AtomicReference<>(null);
            AtomicReference<String> savedErr = new AtomicReference<>(null);

            CSWifiManager.queryWifiStatus(new com.htc.customizedlib.CustomizedService.OperationListener() {
                @Override
                public void onSuccess(String result) {
                    statusRef.set(result);
                    latch.countDown();
                }

                @Override
                public void onFail(int code, String message) {
                    statusErr.set("code=" + code + ", message=" + jsonEscape(message));
                    latch.countDown();
                }
            });

            CSWifiManager.getSavedWifiConfigList(new com.htc.customizedlib.CustomizedService.OperationListener() {
                @Override
                public void onSuccess(String result) {
                    savedRef.set(result);
                    latch.countDown();
                }

                @Override
                public void onFail(int code, String message) {
                    savedErr.set("code=" + code + ", message=" + jsonEscape(message));
                    latch.countDown();
                }
            });

            try {
                latch.await(3, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
            }

            String statusVal = statusRef.get();
            if (statusVal != null) {
                customStatusOut = wifiStatusToJson(statusVal);
            } else {
                String err = statusErr.get();
                customStatusOut = "{\"error\":\"" + (err == null ? "timeout" : err) + "\"}";
            }

            String savedVal = savedRef.get();
            if (savedVal != null) {
                customSavedOut = wifiConfigListToJson(savedVal);
            } else {
                String err = savedErr.get();
                customSavedOut = "{\"error\":\"" + (err == null ? "timeout" : err) + "\"}";
            }
        }

        return "{\n" +
                "  \"status\": \"OK\",\n" +
                "  \"rssi_dbm\": " + wifi.rssiDbm + ",\n" +
                "  \"link_speed_mbps\": " + wifi.linkSpeedMbps + ",\n" +
                "  \"frequency_mhz\": " + wifi.frequencyMhz + ",\n" +
                "  \"band\": \"" + band + "\",\n" +
                "  \"customized_connected\": " + customConnected + ",\n" +
                "  \"customized_wifi_status\": " + customStatusOut + ",\n" +
                "  \"customized_saved_configs\": " + customSavedOut + ",\n" +
                "  \"timestamp\": " + now + "\n" +
                "}";
    }

    private static String getBatteryInfoJson() {
        long now = System.currentTimeMillis();
        if (!isCustomizedReady()) {
            return "{\n" +
                    "  \"status\": \"ERROR\",\n" +
                    "  \"message\": \"CustomizedService not connected\",\n" +
                    "  \"timestamp\": " + now + "\n" +
                    "}";
        }
        BatteryResult battery = fetchBatteryInfo();
        String status = battery.ok ? "OK" : "ERROR";
        return "{\n" +
                "  \"status\": \"" + status + "\",\n" +
                "  \"battery\": " + battery.json + ",\n" +
                "  \"timestamp\": " + now + "\n" +
                "}";
    }

    private static class AsyncResult<T> {
        T result;
        String error;
    }

    private interface StringAsyncSupplier {
        void get(com.htc.customizedlib.CustomizedService.OperationListener listener);
    }

    private static AsyncResult<String> getAsyncStringResult(StringAsyncSupplier supplier, long timeout, TimeUnit unit) {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<String> resultRef = new AtomicReference<>(null);
        AtomicReference<String> errorRef = new AtomicReference<>(null);

        supplier.get(new com.htc.customizedlib.CustomizedService.OperationListener() {
            @Override
            public void onSuccess(String result) {
                resultRef.set(result);
                latch.countDown();
            }

            @Override
            public void onFail(int code, String message) {
                errorRef.set("code=" + code + ", message=" + jsonEscape(message));
                latch.countDown();
            }
        });

        try {
            latch.await(timeout, unit);
        } catch (InterruptedException ignored) {
        }

        AsyncResult<String> asyncResult = new AsyncResult<>();
        asyncResult.result = resultRef.get();
        asyncResult.error = errorRef.get();
        return asyncResult;
    }

    private static class ScanWifiResponse {
        String status;
        String message;
        String scan;
        long timestamp;
    }

    private static String scanWifiJson() {
        long now = System.currentTimeMillis();
        ScanWifiResponse response = new ScanWifiResponse();
        response.timestamp = now;

        if (!isCustomizedReady()) {
            response.status = "ERROR";
            response.message = "CustomizedService not connected";
            return GSON.toJson(response);
        }

        AsyncResult<String> asyncResult = getAsyncStringResult(CSWifiManager::scanWifi, 5, TimeUnit.SECONDS);

        if (asyncResult.result == null) {
            response.status = "ERROR";
            response.message = asyncResult.error != null ? asyncResult.error : "timeout";
            return GSON.toJson(response);
        }

        response.status = "OK";
        response.scan = asyncResult.result;
        return GSON.toJson(response);
    }

    private static String getFirmwareInfoJson() {
        long now = System.currentTimeMillis();
        if (!isCustomizedReady()) {
            return "{\n" +
                    "  \"status\": \"ERROR\",\n" +
                    "  \"message\": \"CustomizedService not connected\",\n" +
                    "  \"timestamp\": " + now + "\n" +
                "}";
        }
        FirmwareResult firmware = fetchFirmwareInfo();
        String status = firmware.ok ? "OK" : "ERROR";
        return "{\n" +
                "  \"status\": \"" + status + "\",\n" +
                "  \"firmware\": " + firmware.json + ",\n" +
                "  \"timestamp\": " + now + "\n" +
                "}";
    }

    private static String forgetWifiJson(String line) {
        long now = System.currentTimeMillis();
        if (!isCustomizedReady()) {
            return "{\n" +
                    "  \"status\": \"ERROR\",\n" +
                    "  \"message\": \"CustomizedService not connected\",\n" +
                    "  \"timestamp\": " + now + "\n" +
                    "}";
        }

        int pathStart = line.indexOf(' ');
        int pathEnd = line.indexOf(' ', pathStart + 1);
        if (pathStart == -1 || pathEnd == -1) {
            return "{\n" +
                    "  \"status\": \"ERROR\",\n" +
                    "  \"message\": \"Invalid request\",\n" +
                    "  \"timestamp\": " + now + "\n" +
                    "}";
        }
        String path = line.substring(pathStart + 1, pathEnd);
        Map<String, String> queryParams = new HashMap<>();
        int q = path.indexOf('?');
        if (q != -1) {
            parseQuery(path.substring(q + 1), queryParams);
        }
        int networkId = getQueryInt(queryParams, "network_id", -1);
        if (networkId < 0) {
            return "{\n" +
                    "  \"status\": \"ERROR\",\n" +
                    "  \"message\": \"Missing network_id\",\n" +
                    "  \"timestamp\": " + now + "\n" +
                    "}";
        }

        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<String> resultRef = new AtomicReference<>(null);
        AtomicReference<String> errorRef = new AtomicReference<>(null);

        CSWifiManager.NetworkIdParamsOrResult params = new CSWifiManager.NetworkIdParamsOrResult();
        params.networkId = networkId;
        CSWifiManager.forgetWifi(params,
                new com.htc.customizedlib.CustomizedService.OperationListener() {
                    @Override
                    public void onSuccess(String result) {
                        resultRef.set(result);
                        latch.countDown();
                    }

                    @Override
                    public void onFail(int code, String message) {
                        errorRef.set("code=" + code + ", message=" + jsonEscape(message));
                        latch.countDown();
                    }
                });

        try {
            latch.await(3, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
        }

        String error = errorRef.get();
        if (error != null) {
            return "{\n" +
                    "  \"status\": \"ERROR\",\n" +
                    "  \"error\": \"" + error + "\",\n" +
                    "  \"timestamp\": " + now + "\n" +
                    "}";
        }
        if (resultRef.get() == null) {
            return "{\n" +
                    "  \"status\": \"ERROR\",\n" +
                    "  \"error\": \"timeout\",\n" +
                    "  \"timestamp\": " + now + "\n" +
                    "}";
        }
        return "{\n" +
                "  \"status\": \"OK\",\n" +
                "  \"result\": \"" + jsonEscape(resultRef.get()) + "\",\n" +
                "  \"timestamp\": " + now + "\n" +
                "}";
    }

    private static String getIpdJson() {
        long now = System.currentTimeMillis();
        if (!isCustomizedReady()) {
            return "{\n" +
                    "  \"status\": \"ERROR\",\n" +
                    "  \"message\": \"CustomizedService not connected\",\n" +
                    "  \"timestamp\": " + now + "\n" +
                    "}";
        }
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<String> resultRef = new AtomicReference<>(null);
        AtomicReference<String> errorRef = new AtomicReference<>(null);

        IPDManager.getIPD(new com.htc.customizedlib.CustomizedService.OperationListener() {
            @Override
            public void onSuccess(String jsonProprietaryResult) {
                resultRef.set(jsonProprietaryResult);
                latch.countDown();
            }

            @Override
            public void onFail(int errorCode, String errorMessage) {
                errorRef.set("code=" + errorCode + ", message=" + jsonEscape(errorMessage));
                latch.countDown();
            }
        });

        try {
            latch.await(3, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
        }

        return ipdResultJson(now, resultRef.get(), errorRef.get(), "getIPD");
    }

    private static String setIpdJson(String line) {
        long now = System.currentTimeMillis();
        if (!isCustomizedReady()) {
            return "{\n" +
                    "  \"status\": \"ERROR\",\n" +
                    "  \"message\": \"CustomizedService not connected\",\n" +
                    "  \"timestamp\": " + now + "\n" +
                    "}";
        }
        int pathStart = line.indexOf(' ');
        int pathEnd = line.indexOf(' ', pathStart + 1);
        if (pathStart == -1 || pathEnd == -1) {
            return "{\n" +
                    "  \"status\": \"ERROR\",\n" +
                    "  \"message\": \"Invalid request\",\n" +
                    "  \"timestamp\": " + now + "\n" +
                    "}";
        }
        String path = line.substring(pathStart + 1, pathEnd);
        Map<String, String> queryParams = new HashMap<>();
        int q = path.indexOf('?');
        if (q != -1) {
            parseQuery(path.substring(q + 1), queryParams);
        }
        String ipdParam = getQueryParam(queryParams, "ipd");
        if (ipdParam == null || ipdParam.isEmpty()) {
            return "{\n" +
                    "  \"status\": \"ERROR\",\n" +
                    "  \"message\": \"Missing ipd\",\n" +
                    "  \"timestamp\": " + now + "\n" +
                    "}";
        }
        float ipd;
        try {
            ipd = Float.parseFloat(ipdParam);
        } catch (NumberFormatException e) {
            return "{\n" +
                    "  \"status\": \"ERROR\",\n" +
                    "  \"message\": \"Invalid ipd\",\n" +
                    "  \"timestamp\": " + now + "\n" +
                    "}";
        }

        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<String> resultRef = new AtomicReference<>(null);
        AtomicReference<String> errorRef = new AtomicReference<>(null);

        IPDManager.IPDParams params = new IPDManager.IPDParams();
        params.ipd = ipd;
        IPDManager.setIPD(params,
                new com.htc.customizedlib.CustomizedService.OperationListener() {
                    @Override
                    public void onSuccess(String jsonProprietaryResult) {
                        resultRef.set(jsonProprietaryResult);
                        latch.countDown();
                    }

                    @Override
                    public void onFail(int errorCode, String errorMessage) {
                        errorRef.set("code=" + errorCode + ", message=" + jsonEscape(errorMessage));
                        latch.countDown();
                    }
                });

        try {
            latch.await(3, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
        }

        return ipdResultJson(now, resultRef.get(), errorRef.get(), "setIPD");
    }

    private static String triggerAutoIpdJson(boolean withUi) {
        long now = System.currentTimeMillis();
        if (!isCustomizedReady()) {
            return "{\n" +
                    "  \"status\": \"ERROR\",\n" +
                    "  \"message\": \"CustomizedService not connected\",\n" +
                    "  \"timestamp\": " + now + "\n" +
                    "}";
        }
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<String> resultRef = new AtomicReference<>(null);
        AtomicReference<String> errorRef = new AtomicReference<>(null);

        Runnable call = () -> {
            com.htc.customizedlib.CustomizedService.OperationListener listener =
                    new com.htc.customizedlib.CustomizedService.OperationListener() {
                        @Override
                        public void onSuccess(String jsonProprietaryResult) {
                            resultRef.set(jsonProprietaryResult);
                            latch.countDown();
                        }

                        @Override
                        public void onFail(int errorCode, String errorMessage) {
                            errorRef.set("code=" + errorCode + ", message=" + jsonEscape(errorMessage));
                            latch.countDown();
                        }
                    };
            if (withUi) {
                IPDManager.triggerAutoIPDWithUI(listener);
            } else {
                IPDManager.triggerAutoIPD(listener);
            }
        };
        call.run();

        try {
            latch.await(3, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
        }

        return ipdResultJson(now, resultRef.get(), errorRef.get(),
                withUi ? "triggerAutoIPDWithUI" : "triggerAutoIPD");
    }

    private static String getAutoIpdInfoJson() {
        long now = System.currentTimeMillis();
        if (!isCustomizedReady()) {
            return "{\n" +
                    "  \"status\": \"ERROR\",\n" +
                    "  \"message\": \"CustomizedService not connected\",\n" +
                    "  \"timestamp\": " + now + "\n" +
                    "}";
        }
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<String> resultRef = new AtomicReference<>(null);
        AtomicReference<String> errorRef = new AtomicReference<>(null);

        IPDManager.getAutoIPDInfo(new com.htc.customizedlib.CustomizedService.OperationListener() {
            @Override
            public void onSuccess(String jsonProprietaryResult) {
                resultRef.set(jsonProprietaryResult);
                latch.countDown();
            }

            @Override
            public void onFail(int errorCode, String errorMessage) {
                errorRef.set("code=" + errorCode + ", message=" + jsonEscape(errorMessage));
                latch.countDown();
            }
        });

        try {
            latch.await(3, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
        }

        String error = errorRef.get();
        if (error != null) {
            return "{\n" +
                    "  \"status\": \"ERROR\",\n" +
                    "  \"error\": \"" + error + "\",\n" +
                    "  \"timestamp\": " + now + "\n" +
                    "}";
        }
        String raw = resultRef.get();
        if (raw == null) {
            return "{\n" +
                    "  \"status\": \"ERROR\",\n" +
                    "  \"error\": \"timeout\",\n" +
                    "  \"timestamp\": " + now + "\n" +
                    "}";
        }
        try {
            IPDManager.AutoIPDInfoResult info =
                    GSON.fromJson(raw, IPDManager.AutoIPDInfoResult.class);
            if (info == null) {
                return "{\n" +
                        "  \"status\": \"OK\",\n" +
                        "  \"raw\": \"" + jsonEscape(raw) + "\",\n" +
                        "  \"timestamp\": " + now + "\n" +
                        "}";
            }
            return "{\n" +
                    "  \"status\": \"OK\",\n" +
                    "  \"exist\": " + info.exist + ",\n" +
                    "  \"enabled\": " + info.enabled + ",\n" +
                    "  \"timestamp\": " + now + "\n" +
                    "}";
        } catch (Throwable t) {
            return "{\n" +
                    "  \"status\": \"OK\",\n" +
                    "  \"raw\": \"" + jsonEscape(raw) + "\",\n" +
                    "  \"timestamp\": " + now + "\n" +
                    "}";
        }
    }

    private static String ipdResultJson(long now, String raw, String error, String action) {
        if (error != null) {
            return "{\n" +
                    "  \"status\": \"ERROR\",\n" +
                    "  \"action\": \"" + action + "\",\n" +
                    "  \"error\": \"" + error + "\",\n" +
                    "  \"timestamp\": " + now + "\n" +
                    "}";
        }
        if (raw == null) {
            return "{\n" +
                    "  \"status\": \"ERROR\",\n" +
                    "  \"action\": \"" + action + "\",\n" +
                    "  \"error\": \"timeout\",\n" +
                    "  \"timestamp\": " + now + "\n" +
                    "}";
        }
        try {
            IPDManager.IPDResult ipdResult = GSON.fromJson(raw, IPDManager.IPDResult.class);
            if (ipdResult == null) {
                return "{\n" +
                        "  \"status\": \"OK\",\n" +
                        "  \"action\": \"" + action + "\",\n" +
                        "  \"raw\": \"" + jsonEscape(raw) + "\",\n" +
                        "  \"timestamp\": " + now + "\n" +
                        "}";
            }
            return "{\n" +
                    "  \"status\": \"OK\",\n" +
                    "  \"action\": \"" + action + "\",\n" +
                    "  \"ipd\": " + ipdResult.ipd + ",\n" +
                    "  \"timestamp\": " + now + "\n" +
                    "}";
        } catch (Throwable t) {
            return "{\n" +
                    "  \"status\": \"OK\",\n" +
                    "  \"action\": \"" + action + "\",\n" +
                    "  \"raw\": \"" + jsonEscape(raw) + "\",\n" +
                    "  \"timestamp\": " + now + "\n" +
                    "}";
        }
    }

    private static class CustomizedStatusResponse {
        String status = "OK";
        long timestamp;
        boolean customized_connected;
    }

    private static String getCustomizedStatusJson() {
        CustomizedStatusResponse response = new CustomizedStatusResponse();
        response.timestamp = System.currentTimeMillis();
        response.customized_connected = CustomizedService.isConnected();
        return GSON.toJson(response);
    }

    private static class WifiStatusRawResponse {
        String status; // OK or ERROR
        String message; // for errors
        String error; // for errors
        String raw;
        long timestamp;
    }

    private static String getWifiStatusRawJson() {
        long now = System.currentTimeMillis();
        WifiStatusRawResponse response = new WifiStatusRawResponse();
        response.timestamp = now;

        if (!isCustomizedReady()) {
            response.status = "ERROR";
            response.message = "CustomizedService not connected";
            return GSON.toJson(response);
        }
        AtomicReference<String> resultRef = new AtomicReference<>(null);
        AtomicReference<String> errorRef = new AtomicReference<>(null);
        CountDownLatch latch = new CountDownLatch(1);

        CSWifiManager.queryWifiStatus(new com.htc.customizedlib.CustomizedService.OperationListener() {
            @Override
            public void onSuccess(String jsonProprietaryResult) {
                resultRef.set(jsonProprietaryResult);
                latch.countDown();
            }

            @Override
            public void onFail(int errorCode, String errorMessage) {
                errorRef.set("code=" + errorCode + ", message=" + jsonEscape(errorMessage));
                latch.countDown();
            }
        });

        try {
            latch.await(3, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
        }

        String error = errorRef.get();
        if (error != null) {
            response.status = "ERROR";
            response.error = error;
            return GSON.toJson(response);
        }
        String raw = resultRef.get();
        if (raw == null) {
            response.status = "ERROR";
            response.error = "timeout";
            return GSON.toJson(response);
        }
        response.status = "OK";
        response.raw = raw;
        return GSON.toJson(response);
    }

    private static void scheduleProcessShutdown() {
        new Thread(() -> {
            try {
                Thread.sleep(300);
            } catch (InterruptedException ignored) {
            }
            try {
                if (appContext != null) {
                    Intent closeUiIntent = new Intent(appContext.getPackageName() + ".action.CLOSE_UI");
                    closeUiIntent.setPackage(appContext.getPackageName());
                    appContext.sendBroadcast(closeUiIntent);
                }
            } catch (Throwable t) {
                Log.w(TAG, "send close UI broadcast failed: " + t.getMessage());
            }
            try {
                if (appContext != null) {
                    String serviceClassName = appContext.getPackageName() + ".DiagnosticForegroundService";
                    Class<?> serviceClass = Class.forName(serviceClassName);
                    Intent stopServiceIntent = new Intent(appContext, serviceClass);
                    appContext.stopService(stopServiceIntent);
                }
            } catch (Throwable t) {
                Log.w(TAG, "stopService failed: " + t.getMessage());
            }
            try {
                if (appContext != null) {
                    android.app.ActivityManager am = (android.app.ActivityManager)
                            appContext.getSystemService(Context.ACTIVITY_SERVICE);
                    if (am != null) {
                        for (android.app.ActivityManager.AppTask task : am.getAppTasks()) {
                            try {
                                task.finishAndRemoveTask();
                            } catch (Throwable ignored) {
                            }
                        }
                    }
                }
            } catch (Throwable t) {
                Log.w(TAG, "finishAndRemoveTask failed: " + t.getMessage());
            }
            try {
                stop();
            } catch (Throwable t) {
                Log.w(TAG, "Shutdown stop() failed: " + t.getMessage());
            }
            try {
                android.os.Process.killProcess(android.os.Process.myPid());
            } catch (Throwable t) {
                Log.w(TAG, "killProcess failed: " + t.getMessage());
                System.exit(0);
            }
        }, "DiagnosticShutdown").start();
    }

    private static BatteryResult fetchBatteryInfo() {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<String> batteryJson = new AtomicReference<>(null);
        AtomicReference<String> batteryError = new AtomicReference<>(null);

        CustomizedService.getBatteryInfo(new com.htc.customizedlib.BatteryManager.BatteryInfoListener() {
            @Override
            public void onSuccess(com.htc.customizedlib.BatteryManager.BatteryInfo info) {
                String serial = info.serial != null ? jsonEscape(info.serial) : "";
                batteryJson.set("{\"serial\":\"" + serial + "\",\"status\":" + info.status + "}");
                latch.countDown();
            }

            @Override
            public void onFail(int code, String message) {
                batteryError.set("code=" + code + ", message=" + jsonEscape(message));
                latch.countDown();
            }
        });

        try {
            latch.await(3, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
        }

        String out = batteryJson.get();
        if (out == null) {
            String err = batteryError.get();
            out = "{\"error\":\"" + (err == null ? "timeout" : err) + "\"}";
        }
        return new BatteryResult(out, batteryJson.get() != null && batteryError.get() == null);
    }

    private static FirmwareResult fetchFirmwareInfo() {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<String> firmwareJson = new AtomicReference<>(null);
        AtomicReference<String> firmwareError = new AtomicReference<>(null);

        CustomizedService.checkFirmware(new FotaManager.CheckFirmwareListener() {
            @Override
            public void onSuccess(FotaManager.CheckResult result) {
                String current = result.currentVersion != null ? jsonEscape(result.currentVersion) : "";
                String latest = result.latestVersion != null ? jsonEscape(result.latestVersion) : "";
                String note = result.releaseNote != null ? jsonEscape(result.releaseNote) : "";
                String size = result.packageSize != null ? jsonEscape(result.packageSize) : "";
                firmwareJson.set("{\"hasNewVersion\":" + result.hasNewVersion +
                        ",\"currentVersion\":\"" + current +
                        "\",\"latestVersion\":\"" + latest +
                        "\",\"releaseNote\":\"" + note +
                        "\",\"packageSize\":\"" + size +
                        "\",\"forceUpdate\":" + result.forceUpdate + "}");
                latch.countDown();
            }

            @Override
            public void onFail(int code, String message) {
                firmwareError.set("code=" + code + ", message=" + jsonEscape(message));
                latch.countDown();
            }
        });

        try {
            latch.await(3, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
        }

        String out = firmwareJson.get();
        if (out == null) {
            String err = firmwareError.get();
            out = "{\"error\":\"" + (err == null ? "timeout" : err) + "\"}";
        }
        return new FirmwareResult(out, firmwareJson.get() != null && firmwareError.get() == null);
    }

    private static final class BatteryResult {
        final String json;
        final boolean ok;

        BatteryResult(String json, boolean ok) {
            this.json = json;
            this.ok = ok;
        }
    }

    private static final class FirmwareResult {
        final String json;
        final boolean ok;

        FirmwareResult(String json, boolean ok) {
            this.json = json;
            this.ok = ok;
        }
    }

    private static String jsonEscape(String value) {
        if (value == null) {
            return "";
        }
        String json = GSON.toJson(value);
        return json.substring(1, json.length() - 1);
    }

    private static boolean isCustomizedReady() {
        return CustomizedService.isConnected();
    }

    private static String wifiStatusToJson(String raw) {
        try {
            CSWifiManager.WifiStatusResult status =
                    GSON.fromJson(raw, CSWifiManager.WifiStatusResult.class);
            if (status == null) {
                return "{\"raw\":\"" + jsonEscape(raw) + "\"}";
            }
            String ssid = status.ssid != null ? jsonEscape(status.ssid) : "";
            String wifiState = status.wifiState != null ? status.wifiState.toString() : "UNKNOWN";
            String connectionState = status.wifiConnectionState != null
                    ? status.wifiConnectionState.toString()
                    : "UNKNOWN";
            return "{"
                    + "\"wifiState\":\"" + wifiState + "\","
                    + "\"wifiConnectionState\":\"" + connectionState + "\","
                    + "\"ssid\":\"" + ssid + "\","
                    + "\"networkId\":" + status.networkId + ","
                    + "\"frequency\":" + status.frequency + ","
                    + "\"level\":" + status.level
                    + "}";
        } catch (Throwable t) {
            return "{\"raw\":\"" + jsonEscape(raw) + "\"}";
        }
    }

    private static String wifiConfigListToJson(String raw) {
        try {
            CSWifiManager.CSWifiConfigList list =
                    GSON.fromJson(raw, CSWifiManager.CSWifiConfigList.class);
            if (list == null || list.CSWifiConfigs == null) {
                return "{\"raw\":\"" + jsonEscape(raw) + "\"}";
            }
            StringBuilder sb = new StringBuilder();
            sb.append("{\"configs\":[");
            boolean first = true;
            for (com.htc.customizedlib.CSWifiConfig cfg : list.CSWifiConfigs) {
                if (!first) {
                    sb.append(",");
                }
                first = false;
                String ssid = cfg.ssid != null ? jsonEscape(cfg.ssid) : "";
                String security = cfg.securityType != null ? cfg.securityType.toString() : "UNKNOWN";
                sb.append("{")
                        .append("\"ssid\":\"").append(ssid).append("\",")
                        .append("\"securityType\":\"").append(security).append("\",")
                        .append("\"networkId\":").append(cfg.networkId).append(",")
                        .append("\"hidden\":").append(cfg.hidden)
                        .append("}");
            }
            sb.append("]}");
            return sb.toString();
        } catch (Throwable t) {
            return "{\"raw\":\"" + jsonEscape(raw) + "\"}";
        }
    }


    private static double readCpuUsagePercent() {
        try {
            CpuSnapshot first = readCpuSnapshot();
            if (first != null) {
                CpuSnapshot prev = lastCpuSnapshot;
                if (prev == null) {
                    try {
                        Thread.sleep(200);
                    } catch (InterruptedException ignored) {
                    }
                    CpuSnapshot second = readCpuSnapshot();
                    if (second != null) {
                        double value = computeCpuPercent(first, second);
                        lastCpuSnapshot = second;
                        if (value >= 0) {
                            lastCpuPercent = value;
                            lastCpuScope = "system";
                            return value;
                        }
                    }
                    lastCpuSnapshot = first;
                } else {
                    double value = computeCpuPercent(prev, first);
                    lastCpuSnapshot = first;
                    if (value >= 0) {
                        lastCpuPercent = value;
                        lastCpuScope = "system";
                        return value;
                    }
                }
            }
        } catch (Throwable ignored) {
        }

        double procPercent = readProcessCpuPercent();
        if (procPercent >= 0) {
            lastCpuPercent = procPercent;
            lastCpuScope = "process";
            return procPercent;
        }
        lastCpuScope = "unknown";
        return lastCpuPercent;
    }

    private static CpuSnapshot readCpuSnapshot() {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new java.io.FileInputStream("/proc/stat")))) {
            String line = reader.readLine();
            if (line == null || !line.startsWith("cpu ")) {
                return null;
            }
            String[] parts = line.trim().split("\\s+");
            if (parts.length < 5) {
                return null;
            }
            long user = Long.parseLong(parts[1]);
            long nice = Long.parseLong(parts[2]);
            long system = Long.parseLong(parts[3]);
            long idle = Long.parseLong(parts[4]);
            long iowait = parts.length > 5 ? Long.parseLong(parts[5]) : 0;
            long irq = parts.length > 6 ? Long.parseLong(parts[6]) : 0;
            long softirq = parts.length > 7 ? Long.parseLong(parts[7]) : 0;
            long total = user + nice + system + idle + iowait + irq + softirq;
            return new CpuSnapshot(total, idle + iowait);
        } catch (Throwable t) {
            return null;
        }
    }

    private static double computeCpuPercent(CpuSnapshot prev, CpuSnapshot current) {
        long totalDelta = current.total - prev.total;
        long idleDelta = current.idle - prev.idle;
        if (totalDelta <= 0) {
            return -1.0;
        }
        return (totalDelta - idleDelta) * 100.0 / totalDelta;
    }

    private static double readProcessCpuPercent() {
        long cpuMs = android.os.Process.getElapsedCpuTime();
        long wallMs = SystemClock.elapsedRealtime();
        long prevCpu = lastProcCpuMs;
        long prevWall = lastProcWallMs;
        lastProcCpuMs = cpuMs;
        lastProcWallMs = wallMs;
        if (prevWall == 0 || wallMs <= prevWall) {
            return -1.0;
        }
        long cpuDelta = cpuMs - prevCpu;
        long wallDelta = wallMs - prevWall;
        if (cpuDelta < 0 || wallDelta <= 0) {
            return -1.0;
        }
        int cores = Math.max(1, Runtime.getRuntime().availableProcessors());
        double percent = (cpuDelta * 100.0 / wallDelta) / cores;
        return Math.max(0.0, Math.min(100.0, percent));
    }

    private static MemoryStats readMemoryStats() {
        MemoryStats stats = new MemoryStats();
        if (appContext == null) {
            return stats;
        }
        android.app.ActivityManager am =
                (android.app.ActivityManager) appContext.getSystemService(Context.ACTIVITY_SERVICE);
        if (am == null) {
            return stats;
        }
        android.app.ActivityManager.MemoryInfo info = new android.app.ActivityManager.MemoryInfo();
        am.getMemoryInfo(info);
        stats.totalBytes = info.totalMem;
        stats.availableBytes = info.availMem;
        stats.usedBytes = Math.max(0, stats.totalBytes - stats.availableBytes);
        return stats;
    }

    private static BatteryStats readBatteryStats() {
        BatteryStats stats = new BatteryStats();
        if (appContext == null) {
            return stats;
        }
        BatteryManager bm =
                (BatteryManager) appContext.getSystemService(Context.BATTERY_SERVICE);
        if (bm == null) {
            return stats;
        }
        int percent = bm.getIntProperty(android.os.BatteryManager.BATTERY_PROPERTY_CAPACITY);
        int status = bm.getIntProperty(android.os.BatteryManager.BATTERY_PROPERTY_STATUS);
        boolean charging = status == android.os.BatteryManager.BATTERY_STATUS_CHARGING ||
                status == android.os.BatteryManager.BATTERY_STATUS_FULL;
        stats.percent = percent;
        stats.charging = charging;
        Intent intent = appContext.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        if (intent != null) {
            int temp = intent.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1);
            if (temp >= 0) {
                stats.tempC = temp / 10.0;
            }
        }
        return stats;
    }

    private static WifiStats readWifiStats() {
        WifiStats stats = new WifiStats();
        try {
            if (appContext == null) {
                return stats;
            }
            android.net.wifi.WifiManager wm =
                    (android.net.wifi.WifiManager) appContext.getSystemService(Context.WIFI_SERVICE);
            if (wm == null) {
                return stats;
            }
            android.net.wifi.WifiInfo info = wm.getConnectionInfo();
            if (info == null) {
                return stats;
            }
            stats.rssiDbm = info.getRssi();
            stats.linkSpeedMbps = info.getLinkSpeed();
            stats.frequencyMhz = info.getFrequency();
        } catch (Throwable t) {
            // Return defaults on permission/API issues.
        }
        return stats;
    }

    private static ThermalStats readThermalStats() {
        ThermalStats stats = new ThermalStats();
        if (appContext == null) {
            return stats;
        }
        try {
            PowerManager pm = (PowerManager) appContext.getSystemService(Context.POWER_SERVICE);
            if (pm != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                stats.status = pm.getCurrentThermalStatus();
            }
        } catch (Throwable ignored) {
        }
        return stats;
    }

    private static ProcessMemoryStats readProcessMemoryStats() {
        ProcessMemoryStats stats = new ProcessMemoryStats();
        if (appContext == null) {
            return stats;
        }
        android.app.ActivityManager am =
                (android.app.ActivityManager) appContext.getSystemService(Context.ACTIVITY_SERVICE);
        if (am == null) {
            return stats;
        }
        android.os.Debug.MemoryInfo[] infos =
                am.getProcessMemoryInfo(new int[]{android.os.Process.myPid()});
        if (infos != null && infos.length > 0) {
            stats.totalPssKb = infos[0].getTotalPss();
        }
        return stats;
    }

    private static long[] readCpuFreqStats() {
        int coreCount = Runtime.getRuntime().availableProcessors();
        List<Long> freqs = new ArrayList<>();
        for (int i = 0; i < coreCount; i++) {
            String path = "/sys/devices/system/cpu/cpu" + i + "/cpufreq/scaling_cur_freq";
            String value = readFirstLine(path);
            if (value != null) {
                try {
                    long khz = Long.parseLong(value.trim());
                    freqs.add(khz * 1000L);
                } catch (NumberFormatException ignored) {
                }
            }
        }
        long[] result = new long[freqs.size()];
        for (int i = 0; i < freqs.size(); i++) {
            result[i] = freqs.get(i);
        }
        return result;
    }

    private static String readFirstLine(String path) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new java.io.FileInputStream(path)))) {
            return reader.readLine();
        } catch (Throwable t) {
            return null;
        }
    }

    private static void runTest(NetworkTestConfig config) {
        String mode = config.mode == null ? "rtt" : config.mode;
        int payloadBytes = Math.max(16, config.payloadBytes);
        int rateHz = Math.max(1, config.rateHz);
        int durationMs = Math.max(500, config.durationMs);

        int intervalMs = Math.max(1, 1000 / rateHz);
        int totalPackets = Math.max(1, durationMs / intervalMs);

        long[] sendTimes = new long[totalPackets];
        long[] recvTimes = new long[totalPackets];
        Arrays.fill(recvTimes, -1L);

        long startNs = System.nanoTime();
        long durationNs = durationMs * 1_000_000L;
        long nextSendNs = startNs;

        byte[] sendBuffer = new byte[payloadBytes];
        byte[] recvBuffer = new byte[payloadBytes];

        InetAddress targetAddr = null;
        if (!"rx".equalsIgnoreCase(mode)) {
            try {
                targetAddr = InetAddress.getByName(config.targetHost);
            } catch (Throwable t) {
                lastResultJson = "{ \"status\": \"ERROR\", \"message\": \"Invalid target host\", \"timestamp\": " +
                        System.currentTimeMillis() + " }";
                return;
            }
        }

        try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(UDP_PORT))) {
            socket.setSoTimeout(2);
            InetSocketAddress target = null;
            if (targetAddr != null) {
                target = new InetSocketAddress(targetAddr, config.targetPort);
            }

            if ("throughput".equalsIgnoreCase(mode)) {
                long bytesSent = runThroughput(socket, target, payloadBytes, durationMs, config.targetMbps);
                double elapsedSec = durationMs / 1000.0;
                double achievedMbps = (bytesSent * 8.0) / 1_000_000.0 / elapsedSec;
                lastResultJson = "{\n" +
                        "  \"status\": \"DONE\",\n" +
                        "  \"mode\": \"throughput\",\n" +
                        "  \"target\": \"" + config.targetHost + ":" + config.targetPort + "\",\n" +
                        "  \"sent_bytes\": " + bytesSent + ",\n" +
                        "  \"target_mbps\": " + String.format(Locale.US, "%.2f", config.targetMbps) + ",\n" +
                        "  \"achieved_mbps\": " + String.format(Locale.US, "%.2f", achievedMbps) + ",\n" +
                        "  \"duration_ms\": " + durationMs + ",\n" +
                        "  \"payload_bytes\": " + payloadBytes + ",\n" +
                        "  \"timestamp\": " + System.currentTimeMillis() + "\n" +
                        "}";
                return;
            } else if ("rx".equalsIgnoreCase(mode)) {
                ReceiveResult rx = runReceive(socket, durationMs, config.expectedPackets);
                double elapsedSec = durationMs / 1000.0;
                double receivedMbps = (rx.receivedBytes * 8.0) / 1_000_000.0 / elapsedSec;
                double lossPct = rx.expectedPackets > 0
                        ? (rx.expectedPackets - rx.receivedPackets) * 100.0 / rx.expectedPackets
                        : (rx.maxSeq >= 0 ? (rx.maxSeq + 1 - rx.receivedPackets) * 100.0 / (rx.maxSeq + 1) : -1.0);
                lastResultJson = "{\n" +
                        "  \"status\": \"DONE\",\n" +
                        "  \"mode\": \"rx\",\n" +
                        "  \"received_packets\": " + rx.receivedPackets + ",\n" +
                        "  \"expected_packets\": " + rx.expectedPackets + ",\n" +
                        "  \"loss_pct\": " + String.format(Locale.US, "%.2f", lossPct) + ",\n" +
                        "  \"received_bytes\": " + rx.receivedBytes + ",\n" +
                        "  \"received_mbps\": " + String.format(Locale.US, "%.2f", receivedMbps) + ",\n" +
                        "  \"duration_ms\": " + durationMs + ",\n" +
                        "  \"payload_bytes\": " + payloadBytes + ",\n" +
                        "  \"timestamp\": " + System.currentTimeMillis() + "\n" +
                        "}";
                return;
            }

            DatagramPacket recvPacket = new DatagramPacket(recvBuffer, recvBuffer.length);
            int seq = 0;
            while (System.nanoTime() - startNs < durationNs) {
                long now = System.nanoTime();
                if (now >= nextSendNs && seq < totalPackets) {
                    ByteBuffer.wrap(sendBuffer)
                            .order(ByteOrder.BIG_ENDIAN)
                            .putLong(0, seq)
                            .putLong(8, now);
                    DatagramPacket packet = new DatagramPacket(sendBuffer, sendBuffer.length, target);
                    socket.send(packet);
                    sendTimes[seq] = now;
                    seq++;
                    nextSendNs += intervalMs * 1_000_000L;
                }

                try {
                    long waitNs = nextSendNs - System.nanoTime();
                    if (waitNs > 2_000_000L) {
                        int waitMs = (int) Math.min(50L, waitNs / 1_000_000L);
                        socket.setSoTimeout(Math.max(1, waitMs));
                    } else {
                        socket.setSoTimeout(1);
                    }
                    socket.receive(recvPacket);
                    long recvNs = System.nanoTime();
                    if (recvPacket.getLength() >= 16) {
                        ByteBuffer bb = ByteBuffer.wrap(recvPacket.getData(), 0, recvPacket.getLength())
                                .order(ByteOrder.BIG_ENDIAN);
                        long rseq = bb.getLong(0);
                        long sendNs = bb.getLong(8);
                        if (rseq >= 0 && rseq < totalPackets) {
                            int idx = (int) rseq;
                            if (recvTimes[idx] == -1L) {
                                recvTimes[idx] = recvNs;
                                sendTimes[idx] = sendNs;
                            }
                        }
                    }
                } catch (SocketTimeoutException ignored) {
                }
            }

            long drainUntil = System.nanoTime() + 200_000_000L;
            while (System.nanoTime() < drainUntil) {
                try {
                    socket.receive(recvPacket);
                    long recvNs = System.nanoTime();
                    if (recvPacket.getLength() >= 16) {
                        ByteBuffer bb = ByteBuffer.wrap(recvPacket.getData(), 0, recvPacket.getLength())
                                .order(ByteOrder.BIG_ENDIAN);
                        long rseq = bb.getLong(0);
                        long sendNs = bb.getLong(8);
                        if (rseq >= 0 && rseq < totalPackets) {
                            int idx = (int) rseq;
                            if (recvTimes[idx] == -1L) {
                                recvTimes[idx] = recvNs;
                                sendTimes[idx] = sendNs;
                            }
                        }
                    }
                } catch (SocketTimeoutException ignored) {
                }
            }

            int sent = Math.min(seq, totalPackets);
            int received = 0;
            double[] rttsMs = new double[sent];
            int rttCount = 0;
            for (int i = 0; i < sent; i++) {
                if (recvTimes[i] != -1L && sendTimes[i] != 0L) {
                    double rttMs = (recvTimes[i] - sendTimes[i]) / 1_000_000.0;
                    rttsMs[rttCount++] = rttMs;
                    received++;
                }
            }

            double lossPct = sent == 0 ? 100.0 : (sent - received) * 100.0 / sent;
            double avgRtt = rttCount == 0 ? -1.0 : average(rttsMs, rttCount);
            double p95Rtt = rttCount == 0 ? -1.0 : percentile(rttsMs, rttCount, 95.0);
            double p99Rtt = rttCount == 0 ? -1.0 : percentile(rttsMs, rttCount, 99.0);
            double jitterP95 = rttCount <= 1 ? -1.0 : jitterP95(rttsMs, rttCount);

            lastResultJson = "{\n" +
                    "  \"status\": \"DONE\",\n" +
                    "  \"mode\": \"rtt\",\n" +
                    "  \"target\": \"" + config.targetHost + ":" + config.targetPort + "\",\n" +
                    "  \"sent\": " + sent + ",\n" +
                    "  \"received\": " + received + ",\n" +
                    "  \"loss_pct\": " + String.format(Locale.US, "%.2f", lossPct) + ",\n" +
                    "  \"rtt_avg_ms\": " + String.format(Locale.US, "%.2f", avgRtt) + ",\n" +
                    "  \"rtt_p95_ms\": " + String.format(Locale.US, "%.2f", p95Rtt) + ",\n" +
                    "  \"rtt_p99_ms\": " + String.format(Locale.US, "%.2f", p99Rtt) + ",\n" +
                    "  \"jitter_p95_ms\": " + String.format(Locale.US, "%.2f", jitterP95) + ",\n" +
                    "  \"rate_hz\": " + rateHz + ",\n" +
                    "  \"duration_ms\": " + durationMs + ",\n" +
                    "  \"payload_bytes\": " + payloadBytes + ",\n" +
                    "  \"timestamp\": " + System.currentTimeMillis() + "\n" +
                    "}";
        } catch (Throwable t) {
            String msg = "Network error: " + (t.getMessage() != null ? t.getMessage() : t.getClass().getSimpleName());
            lastResultJson = "{ \"status\": \"ERROR\", \"message\": \"" + msg + "\", \"timestamp\": " +
                    System.currentTimeMillis() + " }";
        }
    }

    private static long runThroughput(
            DatagramSocket socket,
            InetSocketAddress target,
            int payloadBytes,
            int durationMs,
            double targetMbps
    ) throws Exception {
        byte[] sendBuffer = new byte[payloadBytes];
        DatagramPacket packet = new DatagramPacket(sendBuffer, sendBuffer.length, target);

        double bytesPerNs = (targetMbps * 1_000_000.0 / 8.0) / 1_000_000_000.0;
        long startNs = System.nanoTime();
        long endNs = startNs + (long) durationMs * 1_000_000L;
        long sentBytes = 0;

        while (System.nanoTime() < endNs && running) {
            long now = System.nanoTime();
            long budget = (long) ((now - startNs) * bytesPerNs) - sentBytes;
            while (budget >= payloadBytes && running) {
                socket.send(packet);
                sentBytes += payloadBytes;
                budget -= payloadBytes;
            }
            Thread.yield();
        }

        return sentBytes;
    }

    private static ReceiveResult runReceive(
            DatagramSocket socket,
            int durationMs,
            int expectedPackets
    ) throws Exception {
        byte[] recvBuffer = new byte[2048];
        DatagramPacket recvPacket = new DatagramPacket(recvBuffer, recvBuffer.length);
        long startNs = System.nanoTime();
        long endNs = startNs + (long) durationMs * 1_000_000L;
        long receivedBytes = 0;
        int receivedPackets = 0;
        long maxSeq = -1;

        while (System.nanoTime() < endNs && running) {
            try {
                socket.receive(recvPacket);
                receivedBytes += recvPacket.getLength();
                receivedPackets += 1;
                if (recvPacket.getLength() >= 8) {
                    ByteBuffer bb = ByteBuffer.wrap(recvPacket.getData(), 0, recvPacket.getLength())
                            .order(ByteOrder.BIG_ENDIAN);
                    long seq = bb.getLong(0);
                    if (seq > maxSeq) {
                        maxSeq = seq;
                    }
                }
            } catch (SocketTimeoutException ignored) {
            }
        }

        ReceiveResult result = new ReceiveResult();
        result.receivedBytes = receivedBytes;
        result.receivedPackets = receivedPackets;
        result.maxSeq = maxSeq;
        result.expectedPackets = expectedPackets;
        return result;
    }

    private static double average(double[] values, int count) {
        double sum = 0.0;
        for (int i = 0; i < count; i++) {
            sum += values[i];
        }
        return sum / count;
    }

    private static double percentile(double[] values, int count, double pct) {
        double[] copy = Arrays.copyOf(values, count);
        Arrays.sort(copy);
        int idx = (int) Math.ceil((pct / 100.0) * count) - 1;
        idx = Math.max(0, Math.min(copy.length - 1, idx));
        return copy[idx];
    }

    private static double jitterP95(double[] values, int count) {
        double[] diffs = new double[count - 1];
        int d = 0;
        for (int i = 1; i < count; i++) {
            diffs[d++] = Math.abs(values[i] - values[i - 1]);
        }
        return percentile(diffs, d, 95.0);
    }

    private static class NetworkTestConfig {
        String targetHost;
        String mode;
        int targetPort = UDP_PORT;
        int durationMs = DEFAULT_DURATION_MS;
        int rateHz = DEFAULT_RATE_HZ;
        int payloadBytes = DEFAULT_PAYLOAD_BYTES;
        double targetMbps = DEFAULT_TARGET_MBPS;
        int expectedPackets = DEFAULT_EXPECTED_PACKETS;

        boolean requiresTarget() {
            return !"rx".equalsIgnoreCase(mode);
        }
    }

    private static class CpuSnapshot {
        long total;
        long idle;

        CpuSnapshot(long total, long idle) {
            this.total = total;
            this.idle = idle;
        }
    }

    private static class MemoryStats {
        long totalBytes;
        long availableBytes;
        long usedBytes;
    }

    private static class BatteryStats {
        int percent = -1;
        boolean charging = false;
        double tempC = -1.0;
    }

    private static class WifiStats {
        int rssiDbm = -1;
        int linkSpeedMbps = -1;
        int frequencyMhz = -1;
    }


    private static class ThermalStats {
        int status = -1;
    }

    private static class ProcessMemoryStats {
        int totalPssKb = -1;
    }

    private static CpuSnapshot lastCpuSnapshot;
    private static double lastCpuPercent = -1.0;
    private static long lastProcCpuMs = 0;
    private static long lastProcWallMs = 0;


    private static class ReceiveResult {
        long receivedBytes;
        int receivedPackets;
        long maxSeq;
        int expectedPackets;
    }
}
