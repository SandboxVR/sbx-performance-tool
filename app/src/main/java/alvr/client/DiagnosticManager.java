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
import java.net.BindException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.LockSupport;

public final class DiagnosticManager {
    private static final String TAG = "DiagnosticManager";
    private static final int UDP_PORT = 9123;
    private static final int HTTP_PORT = 9124;
    private static final int SOCKET_POLL_TIMEOUT_MS = 100;
    private static final long RTT_REPLY_DRAIN_NS = 200_000_000L;
    private static final long COMPLETED_TEST_RETENTION_MS = 5 * 60_000L;
    private static final int MAX_RTT_PACKETS = 1_000_000;

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
    private static Thread wifiReconnectThread;
    private static volatile boolean wifiReconnectRunning = false;
    private static volatile String lastCpuScope = "unknown";
    private static ExecutorService clientExecutor = Executors.newCachedThreadPool();
    private static ExecutorService testExecutor = Executors.newCachedThreadPool();
    private static final ConcurrentHashMap<String, NetworkTestState> tests = new ConcurrentHashMap<>();

    private static final int DEFAULT_LEAK_CHUNK_KB = 4;
    private static final int DEFAULT_LEAK_INTERVAL_MS = 250;
    private static final int DEFAULT_LEAK_MAX_MB = 256;
    private static final int MAX_LEAK_MAX_MB = 9999;

    private static final Object LEAK_LOCK = new Object();
    private static Thread leakThread;
    private static volatile boolean leakRunning = false;
    private static volatile long leakAllocatedBytes = 0L;
    private static volatile int leakChunkCount = 0;
    private static volatile String leakMode = "jni";
    private static volatile int leakChunkBytes = DEFAULT_LEAK_CHUNK_KB * 1024;
    private static volatile int leakIntervalMs = DEFAULT_LEAK_INTERVAL_MS;
    private static volatile long leakMaxBytes = DEFAULT_LEAK_MAX_MB * 1024L * 1024L;
    private static volatile String leakLastError = "";

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
            stopAllTests();
            stopTestExecutor();
            stopMemoryLeak();
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

    private static void ensureTestExecutor() {
        if (testExecutor == null || testExecutor.isShutdown()) {
            testExecutor = Executors.newCachedThreadPool();
        }
    }

    private static void stopTestExecutor() {
        if (testExecutor != null) {
            testExecutor.shutdownNow();
            testExecutor = null;
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
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            String line = reader.readLine();
            if (line == null) {
                return;
            }

            RequestInfo request = parseRequestLine(line);
            if (request == null) {
                sendJsonResponse(socket, "400 Bad Request", buildApiMessage("ERROR", null, "Invalid request"));
                return;
            }

            pruneFinishedTests();

            if ("/start-test".equals(request.path)) {
                NetworkTestConfig config = parseStartRequest(request.queryParams);
                if (config == null) {
                    sendJsonResponse(socket, "400 Bad Request", buildApiMessage("ERROR", null, "Invalid request"));
                    return;
                }
                String validationError = validateNetworkTestConfig(config);
                if (validationError != null) {
                    sendJsonResponse(socket, "400 Bad Request",
                            buildApiMessage("ERROR", config.testId, validationError));
                    return;
                }

                StartTestResponse response = startTest(config);
                sendResponse(socket, response.httpStatus, response.bodyJson, "application/json");
            } else if ("/get-results".equals(request.path)) {
                String testId = getRequiredTestId(request.queryParams);
                if (testId == null) {
                    sendJsonResponse(socket, "400 Bad Request",
                            buildApiMessage("ERROR", null, "Missing test_id query param"));
                    return;
                }
                NetworkTestState state = tests.get(testId);
                if (state == null) {
                    sendJsonResponse(socket, "404 Not Found",
                            buildApiMessage("ERROR", testId, "Unknown test_id"));
                    return;
                }
                sendResponse(socket, "200 OK", state.lastResultJson.get(), "application/json");
            } else if ("/list-tests".equals(request.path)) {
                sendResponse(socket, "200 OK", listTestsJson(), "application/json");
            } else if (line.startsWith("GET /get-hardware-stats")) {
                sendResponse(socket, "200 OK", getHardwareStatsJson(), "application/json");
            } else if (line.startsWith("GET /get-wifi-stats")) {
                sendResponse(socket, "200 OK", getWifiStatsJson(), "application/json");
            } else if (line.startsWith("GET /scan-wifi")) {
                sendResponse(socket, "200 OK", scanWifiJson(), "application/json");
            } else if ("/stop-test".equals(request.path)) {
                String testId = getRequiredTestId(request.queryParams);
                if (testId == null) {
                    sendJsonResponse(socket, "400 Bad Request",
                            buildApiMessage("ERROR", null, "Missing test_id query param"));
                    return;
                }
                NetworkTestState state = tests.get(testId);
                if (state == null) {
                    sendJsonResponse(socket, "404 Not Found",
                            buildApiMessage("ERROR", testId, "Unknown test_id"));
                    return;
                }
                stopTest(state, "Stopped by API request");
                sendResponse(socket, "200 OK", state.lastResultJson.get(), "application/json");
            } else if ("/stop-all-tests".equals(request.path)) {
                stopAllTests();
                sendJsonResponse(socket, "200 OK", buildApiMessage("STOPPED", null, "All active tests stopped"));
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
            } else if ("/start-memory-leak".equals(request.path)) {
                sendResponse(socket, "200 OK", startMemoryLeakJson(request.queryParams), "application/json");
            } else if ("/stop-memory-leak".equals(request.path)) {
                stopMemoryLeak();
                sendResponse(socket, "200 OK", getMemoryLeakStatusJson(), "application/json");
            } else if ("/get-memory-leak-status".equals(request.path)) {
                sendResponse(socket, "200 OK", getMemoryLeakStatusJson(), "application/json");
            } else {
                sendResponse(socket, "404 Not Found",
                        "Endpoints: /start-test?test_id=..., /get-results?test_id=..., /stop-test?test_id=..., /list-tests, /start-memory-leak, /stop-memory-leak, /get-memory-leak-status, /stop-all-tests, /get-hardware-stats, /get-wifi-stats, /scan-wifi, /reboot, /battery, /check-firmware, /forget-wifi, /ipd/get, /ipd/set, /ipd/auto, /ipd/auto-ui, /ipd/auto-info, /customized-status, /query-wifi-status-raw, /shutdown-app",
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

    private static String startMemoryLeakJson(Map<String, String> queryParams) {
        synchronized (LEAK_LOCK) {
            if (leakRunning) {
                return getMemoryLeakStatusJson();
            }

            int requestedChunkKb = getQueryInt(queryParams, "chunk_kb", DEFAULT_LEAK_CHUNK_KB);
            int requestedIntervalMs = getQueryInt(queryParams, "interval_ms", DEFAULT_LEAK_INTERVAL_MS);
            int requestedMaxMb = getQueryInt(queryParams, "max_mb", DEFAULT_LEAK_MAX_MB);

            leakMode = "jni";
            leakChunkBytes = Math.max(256, requestedChunkKb * 1024);
            leakIntervalMs = Math.max(10, requestedIntervalMs);
            leakMaxBytes = Math.max(1L, Math.min(MAX_LEAK_MAX_MB, requestedMaxMb)) * 1024L * 1024L;
            leakAllocatedBytes = 0L;
            leakChunkCount = 0;
            leakLastError = "";
            leakRunning = true;

            final String payload = buildLeakPayload(leakChunkBytes);

            leakThread = new Thread(() -> {
                try {
                    while (leakRunning && !Thread.currentThread().isInterrupted()) {
                        if (leakAllocatedBytes >= leakMaxBytes) {
                            leakRunning = false;
                            break;
                        }

                        JniLeakBridge.nativeLeakString(payload);

                        synchronized (LEAK_LOCK) {
                            leakAllocatedBytes += payload.getBytes(StandardCharsets.UTF_8).length;
                            leakChunkCount += 1;
                        }

                        Thread.sleep(leakIntervalMs);
                    }
                } catch (OutOfMemoryError oom) {
                    leakLastError = "OutOfMemoryError: " +
                            (oom.getMessage() == null ? "allocation failed" : oom.getMessage());
                    leakRunning = false;
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                } catch (Throwable t) {
                    leakLastError = describeThrowable(t);
                    leakRunning = false;
                }
            }, "DiagnosticJniLeak");
            leakThread.start();
        }

        return getMemoryLeakStatusJson();
    }

    private static void stopMemoryLeak() {
        Thread threadToJoin;
        synchronized (LEAK_LOCK) {
            leakRunning = false;
            threadToJoin = leakThread;
            leakThread = null;
        }

        if (threadToJoin != null) {
            threadToJoin.interrupt();
            try {
                threadToJoin.join(500);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }

        synchronized (LEAK_LOCK) {
            leakAllocatedBytes = 0L;
            leakChunkCount = 0;
        }

        System.gc();
    }

    private static String getMemoryLeakStatusJson() {
        LinkedHashMap<String, Object> payload = new LinkedHashMap<>();
        synchronized (LEAK_LOCK) {
            payload.put("status", "OK");
            payload.put("running", leakRunning);
            payload.put("mode", leakMode);
            payload.put("chunk_bytes", leakChunkBytes);
            payload.put("interval_ms", leakIntervalMs);
            payload.put("allocated_bytes", leakAllocatedBytes);
            payload.put("allocated_mb", roundTo2(leakAllocatedBytes / (1024.0 * 1024.0)));
            payload.put("chunk_count", leakChunkCount);
            payload.put("max_bytes", leakMaxBytes);
            payload.put("max_mb", roundTo2(leakMaxBytes / (1024.0 * 1024.0)));
            payload.put("last_error", leakLastError);
            payload.put("timestamp", System.currentTimeMillis());
        }
        return GSON.toJson(payload);
    }

    private static String buildLeakPayload(int targetBytes) {
        int charCount = Math.max(1, targetBytes);
        char[] chars = new char[charCount];
        Arrays.fill(chars, 'L');
        return new String(chars);
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

    private static void sendJsonResponse(Socket socket, String status, Object body) {
        sendResponse(socket, status, GSON.toJson(body), "application/json");
    }

    private static RequestInfo parseRequestLine(String line) {
        int pathStart = line.indexOf(' ');
        int pathEnd = line.indexOf(' ', pathStart + 1);
        if (pathStart == -1 || pathEnd == -1) {
            return null;
        }
        String pathWithQuery = line.substring(pathStart + 1, pathEnd);
        Map<String, String> queryParams = new HashMap<>();
        int q = pathWithQuery.indexOf('?');
        if (q != -1) {
            parseQuery(pathWithQuery.substring(q + 1), queryParams);
        }
        String path = q == -1 ? pathWithQuery : pathWithQuery.substring(0, q);
        return new RequestInfo(path, queryParams);
    }

    private static NetworkTestConfig parseStartRequest(Map<String, String> queryParams) {
        NetworkTestConfig cfg = new NetworkTestConfig();
        cfg.testId = trimToNull(getQueryParam(queryParams, "test_id"));
        cfg.targetHost = getQueryParam(queryParams, "target");
        cfg.mode = normalizeMode(getQueryParam(queryParams, "mode"));
        cfg.port = getQueryInt(queryParams, "port", UDP_PORT);
        cfg.durationMs = getQueryInt(queryParams, "duration_ms", DEFAULT_DURATION_MS);
        cfg.rateHz = getQueryInt(queryParams, "rate_hz", DEFAULT_RATE_HZ);
        cfg.payloadBytes = getQueryInt(queryParams, "payload_bytes", DEFAULT_PAYLOAD_BYTES);
        cfg.targetMbps = getQueryDouble(queryParams, "target_mbps", DEFAULT_TARGET_MBPS);
        cfg.expectedPackets = getQueryInt(queryParams, "expected_packets", DEFAULT_EXPECTED_PACKETS);
        return cfg;
    }

    private static String validateNetworkTestConfig(NetworkTestConfig config) {
        if (config.testId == null || config.testId.isEmpty()) {
            return "Missing test_id query param";
        }
        if (!config.isSupportedMode()) {
            return "Invalid mode. Expected rtt, rx, or throughput";
        }
        if (config.port < 1 || config.port > 65535) {
            return "Invalid port";
        }
        if (config.requiresTarget() && trimToNull(config.targetHost) == null) {
            return "Missing target query param";
        }
        return null;
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
            String key = decodeQueryComponent(pair.substring(0, eq));
            String value = decodeQueryComponent(pair.substring(eq + 1));
            params.put(key, value);
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

    private static String decodeQueryComponent(String value) {
        try {
            return URLDecoder.decode(value, "UTF-8");
        } catch (Exception e) {
            return value;
        }
    }

    private static String getRequiredTestId(Map<String, String> queryParams) {
        return trimToNull(getQueryParam(queryParams, "test_id"));
    }

    private static String normalizeMode(String mode) {
        if (mode == null || mode.isEmpty()) {
            return "rtt";
        }
        return mode.toLowerCase(Locale.US);
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static LinkedHashMap<String, Object> buildApiMessage(String status, String testId, String message) {
        LinkedHashMap<String, Object> body = new LinkedHashMap<>();
        body.put("status", status);
        if (testId != null) {
            body.put("test_id", testId);
        }
        body.put("message", message);
        body.put("timestamp", System.currentTimeMillis());
        return body;
    }

    private static StartTestResponse startTest(NetworkTestConfig config) {
        synchronized (LOCK) {
            pruneFinishedTestsLocked();

            NetworkTestState existingState = tests.get(config.testId);
            if (existingState != null) {
                if (existingState.running.get()) {
                    return new StartTestResponse("409 Conflict",
                            GSON.toJson(buildApiMessage("ERROR", config.testId, "test_id already exists")));
                }
                tests.remove(config.testId, existingState);
            }

            if (config.bindsExclusivePort()) {
                for (NetworkTestState existing : tests.values()) {
                    if (existing.running.get()
                            && existing.config.bindsExclusivePort()
                            && existing.config.port == config.port) {
                        String msg = "UDP port " + config.port + " is already in use by test_id " + existing.testId;
                        return new StartTestResponse("409 Conflict",
                                GSON.toJson(buildApiMessage("ERROR", config.testId, msg)));
                    }
                }
            }

            ensureTestExecutor();

            NetworkTestState state = new NetworkTestState(config);
            publishRunningResult(state, "Test in progress...");
            tests.put(config.testId, state);

            try {
                state.future = testExecutor.submit(() -> runTest(state));
                return new StartTestResponse("200 OK", state.lastResultJson.get());
            } catch (Throwable t) {
                tests.remove(config.testId);
                String msg = "Failed to start test: " + describeThrowable(t);
                return new StartTestResponse("500 Internal Server Error",
                        GSON.toJson(buildApiMessage("ERROR", config.testId, msg)));
            }
        }
    }

    private static void stopAllTests() {
        for (NetworkTestState state : tests.values()) {
            stopTest(state, "Stopped by API request");
        }
    }

    private static void stopTest(NetworkTestState state, String message) {
        if (state == null) {
            return;
        }

        boolean wasRunning = state.running.getAndSet(false);
        if (wasRunning) {
            state.status = "STOPPED";
            state.endTimeMs = System.currentTimeMillis();
            state.lastResultJson.set(GSON.toJson(buildStoppedPayload(state, message)));
        }

        closeTestSocket(state);

        Future<?> future = state.future;
        if (future != null) {
            try {
                future.cancel(true);
            } catch (Throwable ignored) {
            }
        }
    }

    private static void pruneFinishedTests() {
        synchronized (LOCK) {
            pruneFinishedTestsLocked();
        }
    }

    private static void pruneFinishedTestsLocked() {
        long now = System.currentTimeMillis();
        for (Map.Entry<String, NetworkTestState> entry : tests.entrySet()) {
            NetworkTestState state = entry.getValue();
            if (state.running.get()) {
                continue;
            }
            long finishedAt = state.endTimeMs;
            if (finishedAt != 0L && now - finishedAt > COMPLETED_TEST_RETENTION_MS) {
                tests.remove(entry.getKey(), state);
            }
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
        String status;
        String message;
        String error;
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

    private static void publishRunningResult(NetworkTestState state, String message) {
        state.status = "RUNNING";
        LinkedHashMap<String, Object> payload = baseTestPayload(state, "RUNNING");
        payload.put("message", message);
        payload.put("port", state.config.port);
        payload.put("duration_ms", state.config.durationMs);
        payload.put("payload_bytes", state.config.payloadBytes);
        if ("rtt".equals(state.config.mode)) {
            payload.put("rate_hz", state.config.rateHz);
        } else if ("throughput".equals(state.config.mode)) {
            payload.put("target_mbps", roundTo2(state.config.targetMbps));
        }
        if (state.config.requiresTarget()) {
            payload.put("target", state.config.targetDescription());
        }
        state.lastResultJson.set(GSON.toJson(payload));
    }

    private static LinkedHashMap<String, Object> buildStoppedPayload(NetworkTestState state, String message) {
        LinkedHashMap<String, Object> payload = baseTestPayload(state, "STOPPED");
        payload.put("message", message);
        payload.put("duration_ms", Math.max(0L, state.endTimeMs - state.startTimeMs));
        return payload;
    }

    private static LinkedHashMap<String, Object> baseTestPayload(NetworkTestState state, String status) {
        LinkedHashMap<String, Object> payload = new LinkedHashMap<>();
        payload.put("status", status);
        payload.put("test_id", state.testId);
        payload.put("mode", state.config.mode);
        payload.put("timestamp", System.currentTimeMillis());
        return payload;
    }

    private static void publishResult(NetworkTestState state, LinkedHashMap<String, Object> payload) {
        state.status = (String) payload.get("status");
        state.endTimeMs = System.currentTimeMillis();
        state.lastResultJson.set(GSON.toJson(payload));
    }

    private static void publishError(NetworkTestState state, String message) {
        if ("STOPPED".equals(state.status)) {
            return;
        }
        LinkedHashMap<String, Object> payload = baseTestPayload(state, "ERROR");
        payload.put("message", message);
        publishResult(state, payload);
    }

    private static void registerTestSocket(NetworkTestState state, DatagramSocket socket) {
        state.socketRef.set(socket);
        if (!state.running.get() && !socket.isClosed()) {
            socket.close();
        }
    }

    private static void closeTestSocket(NetworkTestState state) {
        DatagramSocket socket = state.socketRef.getAndSet(null);
        if (socket != null) {
            try {
                socket.close();
            } catch (Throwable ignored) {
            }
        }
    }

    private static boolean isTestRunning(NetworkTestState state) {
        return state.running.get() && !Thread.currentThread().isInterrupted();
    }

    private static void runTest(NetworkTestState state) {
        NetworkTestConfig config = state.config;
        String mode = config.mode;
        int payloadBytes = Math.max("rtt".equals(mode) ? 16 : 1, config.payloadBytes);
        int rateHz = Math.max(1, config.rateHz);
        int durationMs = Math.max(100, config.durationMs);

        DatagramSocket socket = null;
        try {
            if ("rx".equals(mode)) {
                socket = new DatagramSocket(null);
                socket.setReuseAddress(false);
                socket.bind(new InetSocketAddress(config.port));
                socket.setSoTimeout(SOCKET_POLL_TIMEOUT_MS);
                registerTestSocket(state, socket);

                ReceiveResult rx = runReceive(state, socket, durationMs, config.expectedPackets);
                if (!state.running.get() || "STOPPED".equals(state.status)) {
                    return;
                }

                double elapsedSec = Math.max(0.001, durationMs / 1000.0);
                double receivedMbps = (rx.receivedBytes * 8.0) / 1_000_000.0 / elapsedSec;
                double lossPct = rx.expectedPackets > 0
                        ? (rx.expectedPackets - rx.receivedPackets) * 100.0 / rx.expectedPackets
                        : (rx.maxSeq >= 0 ? (rx.maxSeq + 1 - rx.receivedPackets) * 100.0 / (rx.maxSeq + 1) : -1.0);

                LinkedHashMap<String, Object> payload = baseTestPayload(state, "DONE");
                payload.put("received_packets", rx.receivedPackets);
                payload.put("expected_packets", rx.expectedPackets);
                payload.put("loss_pct", roundTo2(lossPct));
                payload.put("received_bytes", rx.receivedBytes);
                payload.put("received_mbps", roundTo2(receivedMbps));
                payload.put("duration_ms", durationMs);
                payload.put("payload_bytes", payloadBytes);
                publishResult(state, payload);
                return;
            }

            InetAddress targetAddress = InetAddress.getByName(config.targetHost);
            InetSocketAddress target = new InetSocketAddress(targetAddress, config.port);

            socket = new DatagramSocket();
            socket.connect(target);
            socket.setSoTimeout(SOCKET_POLL_TIMEOUT_MS);
            registerTestSocket(state, socket);

            if ("throughput".equals(mode)) {
                long bytesSent = runThroughput(state, socket, payloadBytes, durationMs, config.targetMbps);
                if (!state.running.get() || "STOPPED".equals(state.status)) {
                    return;
                }

                double elapsedSec = Math.max(0.001, durationMs / 1000.0);
                double achievedMbps = (bytesSent * 8.0) / 1_000_000.0 / elapsedSec;

                LinkedHashMap<String, Object> payload = baseTestPayload(state, "DONE");
                payload.put("target", config.targetDescription());
                payload.put("sent_bytes", bytesSent);
                payload.put("target_mbps", roundTo2(config.targetMbps));
                payload.put("achieved_mbps", roundTo2(achievedMbps));
                payload.put("duration_ms", durationMs);
                payload.put("payload_bytes", payloadBytes);
                publishResult(state, payload);
                return;
            }

            RttResult rtt = runRtt(state, socket, payloadBytes, rateHz, durationMs);
            if (!state.running.get() || "STOPPED".equals(state.status)) {
                return;
            }

            LinkedHashMap<String, Object> payload = baseTestPayload(state, "DONE");
            payload.put("target", config.targetDescription());
            payload.put("sent", rtt.sentPackets);
            payload.put("received", rtt.receivedPackets);
            payload.put("loss_pct", roundTo2(rtt.lossPct));
            payload.put("rtt_avg_ms", roundTo2(rtt.averageRttMs));
            payload.put("rtt_p95_ms", roundTo2(rtt.p95RttMs));
            payload.put("rtt_p99_ms", roundTo2(rtt.p99RttMs));
            payload.put("jitter_p95_ms", roundTo2(rtt.jitterP95Ms));
            payload.put("rate_hz", rateHz);
            payload.put("duration_ms", durationMs);
            payload.put("payload_bytes", payloadBytes);
            publishResult(state, payload);
        } catch (BindException e) {
            publishError(state, "UDP port " + config.port + " is already in use");
        } catch (Throwable t) {
            if (!state.running.get() || "STOPPED".equals(state.status)) {
                return;
            }
            publishError(state, "Network error: " + describeThrowable(t));
        } finally {
            state.running.set(false);
            closeTestSocket(state);
            if (socket != null && !socket.isClosed()) {
                try {
                    socket.close();
                } catch (Throwable ignored) {
                }
            }
            if (state.endTimeMs == 0L) {
                state.endTimeMs = System.currentTimeMillis();
            }
            state.future = null;
        }
    }

    private static long runThroughput(
            NetworkTestState state,
            DatagramSocket socket,
            int payloadBytes,
            int durationMs,
            double targetMbps
    ) throws Exception {
        byte[] sendBuffer = new byte[payloadBytes];
        DatagramPacket packet = new DatagramPacket(sendBuffer, sendBuffer.length);

        double bytesPerNs = (Math.max(0.01, targetMbps) * 1_000_000.0 / 8.0) / 1_000_000_000.0;
        long startNs = System.nanoTime();
        long endNs = startNs + (long) durationMs * 1_000_000L;
        long sentBytes = 0;

        while (System.nanoTime() < endNs && isTestRunning(state)) {
            long now = System.nanoTime();
            long budget = (long) ((now - startNs) * bytesPerNs) - sentBytes;
            if (budget < payloadBytes) {
                long waitNs = (long) Math.ceil((payloadBytes - budget) / bytesPerNs);
                LockSupport.parkNanos(Math.max(50_000L, Math.min(waitNs, 1_000_000L)));
                continue;
            }

            while (budget >= payloadBytes && isTestRunning(state)) {
                socket.send(packet);
                sentBytes += payloadBytes;
                budget -= payloadBytes;
            }
        }

        return sentBytes;
    }

    private static ReceiveResult runReceive(
            NetworkTestState state,
            DatagramSocket socket,
            int durationMs,
            int expectedPackets
    ) throws Exception {
        byte[] recvBuffer = new byte[2048];
        DatagramPacket recvPacket = new DatagramPacket(recvBuffer, recvBuffer.length);
        long endNs = System.nanoTime() + (long) durationMs * 1_000_000L;
        long receivedBytes = 0;
        int receivedPackets = 0;
        long maxSeq = -1;
        ByteOrder sequenceByteOrder = null;

        while (System.nanoTime() < endNs && isTestRunning(state)) {
            try {
                socket.receive(recvPacket);
                receivedBytes += recvPacket.getLength();
                receivedPackets += 1;
                if (recvPacket.getLength() >= 8) {
                    if (sequenceByteOrder == null) {
                        long bigEndianSeq = readSequenceNumber(recvPacket.getData(), recvPacket.getLength(),
                                ByteOrder.BIG_ENDIAN);
                        long littleEndianSeq = readSequenceNumber(recvPacket.getData(), recvPacket.getLength(),
                                ByteOrder.LITTLE_ENDIAN);
                        sequenceByteOrder = chooseSequenceByteOrder(bigEndianSeq, littleEndianSeq,
                                expectedPackets, receivedPackets, maxSeq);
                    }

                    long seq = readSequenceNumber(recvPacket.getData(), recvPacket.getLength(), sequenceByteOrder);
                    if (seq > maxSeq) {
                        maxSeq = seq;
                    }
                }
            } catch (SocketTimeoutException ignored) {
            } catch (SocketException e) {
                if (!state.running.get()) {
                    break;
                }
                throw e;
            }
        }

        ReceiveResult result = new ReceiveResult();
        result.receivedBytes = receivedBytes;
        result.receivedPackets = receivedPackets;
        result.maxSeq = maxSeq;
        result.expectedPackets = expectedPackets;
        return result;
    }

    private static long readSequenceNumber(byte[] data, int length, ByteOrder byteOrder) {
        if (length < 8) {
            return -1;
        }
        return ByteBuffer.wrap(data, 0, length).order(byteOrder).getLong(0);
    }

    private static ByteOrder chooseSequenceByteOrder(
            long bigEndianSeq,
            long littleEndianSeq,
            int expectedPackets,
            int receivedPackets,
            long currentMaxSeq
    ) {
        if (expectedPackets > 0) {
            long expectedUpperBound = Math.max(expectedPackets * 4L, 1024L);
            boolean bigPlausible = bigEndianSeq >= 0 && bigEndianSeq <= expectedUpperBound;
            boolean littlePlausible = littleEndianSeq >= 0 && littleEndianSeq <= expectedUpperBound;
            if (bigPlausible != littlePlausible) {
                return bigPlausible ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
            }
        }

        long rollingUpperBound = Math.max(4096L, Math.max(currentMaxSeq + 4096L, receivedPackets + 4096L));
        boolean bigPlausible = bigEndianSeq >= 0 && bigEndianSeq <= rollingUpperBound;
        boolean littlePlausible = littleEndianSeq >= 0 && littleEndianSeq <= rollingUpperBound;
        if (bigPlausible != littlePlausible) {
            return bigPlausible ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
        }

        if (currentMaxSeq >= 0) {
            long nextExpectedSeq = currentMaxSeq + 1;
            long bigDistance = Math.abs(bigEndianSeq - nextExpectedSeq);
            long littleDistance = Math.abs(littleEndianSeq - nextExpectedSeq);
            if (bigDistance != littleDistance) {
                return bigDistance < littleDistance ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
            }
        }

        return bigEndianSeq <= littleEndianSeq ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
    }

    private static RttResult runRtt(
            NetworkTestState state,
            DatagramSocket socket,
            int payloadBytes,
            int rateHz,
            int durationMs
    ) throws Exception {
        long requestedPackets = (long) Math.ceil((durationMs / 1000.0) * rateHz);
        if (requestedPackets > MAX_RTT_PACKETS) {
            throw new IllegalArgumentException("RTT test exceeds max packet count of " + MAX_RTT_PACKETS);
        }

        int totalPackets = (int) Math.max(1L, requestedPackets);
        long intervalNs = Math.max(1L, Math.round(1_000_000_000.0 / rateHz));
        long[] rttNsBySeq = new long[totalPackets];
        Arrays.fill(rttNsBySeq, -1L);

        AtomicBoolean senderDone = new AtomicBoolean(false);
        AtomicLong drainDeadlineNs = new AtomicLong(Long.MAX_VALUE);
        AtomicReference<Throwable> receiverError = new AtomicReference<>(null);

        Thread receiverThread = new Thread(() -> {
            byte[] recvBuffer = new byte[Math.max(payloadBytes, 2048)];
            DatagramPacket recvPacket = new DatagramPacket(recvBuffer, recvBuffer.length);

            while (!Thread.currentThread().isInterrupted()) {
                if (!state.running.get()) {
                    break;
                }
                if (senderDone.get() && System.nanoTime() >= drainDeadlineNs.get()) {
                    break;
                }

                try {
                    socket.receive(recvPacket);
                    long recvNs = System.nanoTime();
                    if (recvPacket.getLength() < 16) {
                        continue;
                    }

                    ByteBuffer bb = ByteBuffer.wrap(recvPacket.getData(), 0, recvPacket.getLength())
                            .order(ByteOrder.BIG_ENDIAN);
                    long seq = bb.getLong(0);
                    long sendNs = bb.getLong(8);
                    if (seq >= 0 && seq < rttNsBySeq.length) {
                        int index = (int) seq;
                        if (rttNsBySeq[index] == -1L && recvNs >= sendNs) {
                            rttNsBySeq[index] = recvNs - sendNs;
                        }
                    }
                } catch (SocketTimeoutException ignored) {
                } catch (SocketException e) {
                    if (state.running.get()) {
                        receiverError.compareAndSet(null, e);
                    }
                    break;
                } catch (Throwable t) {
                    receiverError.compareAndSet(null, t);
                    break;
                }
            }
        }, "DiagnosticRttReceiver-" + state.testId);
        receiverThread.start();

        int sent = 0;
        try {
            byte[] sendBuffer = new byte[payloadBytes];
            ByteBuffer sendHeader = ByteBuffer.wrap(sendBuffer).order(ByteOrder.BIG_ENDIAN);
            DatagramPacket sendPacket = new DatagramPacket(sendBuffer, sendBuffer.length);
            long startNs = System.nanoTime();

            while (sent < totalPackets && isTestRunning(state)) {
                long scheduledNs = startNs + sent * intervalNs;
                long waitNs = scheduledNs - System.nanoTime();
                if (waitNs > 0L) {
                    LockSupport.parkNanos(Math.min(waitNs, 200_000L));
                    continue;
                }

                long sendNs = System.nanoTime();
                sendHeader.putLong(0, sent);
                sendHeader.putLong(8, sendNs);
                socket.send(sendPacket);
                sent += 1;

                Throwable failure = receiverError.get();
                if (failure != null) {
                    throw new RuntimeException("RTT receive failed", failure);
                }
            }
        } finally {
            senderDone.set(true);
            drainDeadlineNs.set(System.nanoTime() + RTT_REPLY_DRAIN_NS);
            joinThread(receiverThread, TimeUnit.NANOSECONDS.toMillis(RTT_REPLY_DRAIN_NS) + SOCKET_POLL_TIMEOUT_MS + 50L);
            if (receiverThread.isAlive()) {
                receiverThread.interrupt();
            }
        }

        Throwable failure = receiverError.get();
        if (failure != null && isTestRunning(state)) {
            if (failure instanceof Exception) {
                throw (Exception) failure;
            }
            throw new RuntimeException(failure);
        }

        double[] rttsMs = new double[sent];
        int rttCount = 0;
        for (int i = 0; i < sent; i++) {
            if (rttNsBySeq[i] >= 0L) {
                rttsMs[rttCount++] = rttNsBySeq[i] / 1_000_000.0;
            }
        }

        RttResult result = new RttResult();
        result.sentPackets = sent;
        result.receivedPackets = rttCount;
        result.lossPct = sent == 0 ? 100.0 : (sent - rttCount) * 100.0 / sent;
        result.averageRttMs = rttCount == 0 ? -1.0 : average(rttsMs, rttCount);
        result.p95RttMs = rttCount == 0 ? -1.0 : percentile(rttsMs, rttCount, 95.0);
        result.p99RttMs = rttCount == 0 ? -1.0 : percentile(rttsMs, rttCount, 99.0);
        result.jitterP95Ms = rttCount <= 1 ? -1.0 : jitterP95(rttsMs, rttCount);
        return result;
    }

    private static void joinThread(Thread thread, long timeoutMs) {
        try {
            thread.join(timeoutMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static double roundTo2(double value) {
        if (value < 0.0) {
            return value;
        }
        return Math.round(value * 100.0) / 100.0;
    }

    private static String describeThrowable(Throwable t) {
        Throwable current = t;
        while (current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
        }
        String message = current.getMessage();
        return message != null ? message : current.getClass().getSimpleName();
    }

    private static String listTestsJson() {
        List<LinkedHashMap<String, Object>> summaries = new ArrayList<>();
        for (NetworkTestState state : tests.values()) {
            summaries.add(buildTestSummary(state));
        }
        summaries.sort((left, right) ->
                String.valueOf(left.get("test_id")).compareTo(String.valueOf(right.get("test_id"))));

        LinkedHashMap<String, Object> payload = new LinkedHashMap<>();
        payload.put("status", "OK");
        payload.put("tests", summaries);
        payload.put("timestamp", System.currentTimeMillis());
        return GSON.toJson(payload);
    }

    private static LinkedHashMap<String, Object> buildTestSummary(NetworkTestState state) {
        LinkedHashMap<String, Object> summary = new LinkedHashMap<>();
        summary.put("test_id", state.testId);
        summary.put("mode", state.config.mode);
        summary.put("status", state.status);
        summary.put("running", state.running.get());
        summary.put("start_time_ms", state.startTimeMs);
        if (state.endTimeMs != 0L) {
            summary.put("end_time_ms", state.endTimeMs);
        }
        summary.put("port", state.config.port);
        summary.put("duration_ms", state.config.durationMs);
        summary.put("payload_bytes", state.config.payloadBytes);
        if ("rtt".equals(state.config.mode)) {
            summary.put("rate_hz", state.config.rateHz);
        }
        if ("throughput".equals(state.config.mode)) {
            summary.put("target_mbps", roundTo2(state.config.targetMbps));
        }
        if (state.config.requiresTarget()) {
            summary.put("target", state.config.targetDescription());
        }
        return summary;
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

    private static class RequestInfo {
        final String path;
        final Map<String, String> queryParams;

        RequestInfo(String path, Map<String, String> queryParams) {
            this.path = path;
            this.queryParams = queryParams;
        }
    }

    private static class StartTestResponse {
        final String httpStatus;
        final String bodyJson;

        StartTestResponse(String httpStatus, String bodyJson) {
            this.httpStatus = httpStatus;
            this.bodyJson = bodyJson;
        }
    }

    private static class NetworkTestConfig {
        String testId;
        String targetHost;
        String mode = "rtt";
        int port = UDP_PORT;
        int durationMs = DEFAULT_DURATION_MS;
        int rateHz = DEFAULT_RATE_HZ;
        int payloadBytes = DEFAULT_PAYLOAD_BYTES;
        double targetMbps = DEFAULT_TARGET_MBPS;
        int expectedPackets = DEFAULT_EXPECTED_PACKETS;

        boolean requiresTarget() {
            return !"rx".equals(mode);
        }

        boolean bindsExclusivePort() {
            return "rx".equals(mode);
        }

        boolean isSupportedMode() {
            return "rtt".equals(mode) || "rx".equals(mode) || "throughput".equals(mode);
        }

        String targetDescription() {
            return targetHost + ":" + port;
        }
    }

    private static class NetworkTestState {
        final String testId;
        final NetworkTestConfig config;
        final long startTimeMs = System.currentTimeMillis();
        final AtomicBoolean running = new AtomicBoolean(true);
        final AtomicReference<String> lastResultJson = new AtomicReference<>(
                GSON.toJson(buildApiMessage("IDLE", null, "No test state yet")));
        final AtomicReference<DatagramSocket> socketRef = new AtomicReference<>(null);
        volatile Future<?> future;
        volatile String status = "RUNNING";
        volatile long endTimeMs = 0L;

        NetworkTestState(NetworkTestConfig config) {
            this.testId = config.testId;
            this.config = config;
        }
    }

    private static class RttResult {
        int sentPackets;
        int receivedPackets;
        double lossPct;
        double averageRttMs;
        double p95RttMs;
        double p99RttMs;
        double jitterP95Ms;
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
