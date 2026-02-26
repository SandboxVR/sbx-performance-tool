package com.sandboxvr.perform2;

import android.Manifest;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.text.method.LinkMovementMethod;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import java.net.Inet4Address;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.Enumeration;

public class MainActivity extends AppCompatActivity {
    private static final int REQ_POST_NOTIFICATIONS = 100;
    private static final String ACTION_CLOSE_UI = "com.sandboxvr.perform2.action.CLOSE_UI";
    private TextView statusView;
    private TextView endpointView;
    private boolean serviceRequested;
    private final BroadcastReceiver closeUiReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (intent == null || !ACTION_CLOSE_UI.equals(intent.getAction())) {
                return;
            }
            closeUiAndReturnHome();
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        statusView = findViewById(R.id.statusText);
        endpointView = findViewById(R.id.endpointText);
        endpointView.setMovementMethod(LinkMovementMethod.getInstance());

        findViewById(R.id.startButton).setOnClickListener(v -> {
            ensureNotificationPermissionIfNeeded();
            DiagnosticForegroundService.start(this);
            serviceRequested = true;
            refreshUi();
        });

        findViewById(R.id.stopButton).setOnClickListener(v -> {
            DiagnosticForegroundService.stop(this);
            serviceRequested = false;
            refreshUi();
        });

        findViewById(R.id.refreshButton).setOnClickListener(v -> refreshUi());

        if (savedInstanceState != null) {
            serviceRequested = savedInstanceState.getBoolean("serviceRequested", false);
        }
        ensureNotificationPermissionIfNeeded();
        if (savedInstanceState == null) {
            DiagnosticForegroundService.start(this);
            serviceRequested = true;
        }
        registerCloseUiReceiver();
        refreshUi();
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        outState.putBoolean("serviceRequested", serviceRequested);
        super.onSaveInstanceState(outState);
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshUi();
    }

    @Override
    protected void onDestroy() {
        try {
            unregisterReceiver(closeUiReceiver);
        } catch (Throwable ignored) {
        }
        super.onDestroy();
    }

    private void refreshUi() {
        statusView.setText(serviceRequested
                ? getString(R.string.status_running_hint)
                : getString(R.string.status_stopped_hint));
        statusView.setBackgroundResource(serviceRequested
                ? R.drawable.chip_status_running
                : R.drawable.chip_status_stopped);
        endpointView.setText(buildEndpointText());
    }

    private void ensureNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            return;
        }
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                == PackageManager.PERMISSION_GRANTED) {
            return;
        }
        ActivityCompat.requestPermissions(
                this,
                new String[]{Manifest.permission.POST_NOTIFICATIONS},
                REQ_POST_NOTIFICATIONS
        );
    }

    private void registerCloseUiReceiver() {
        IntentFilter filter = new IntentFilter(ACTION_CLOSE_UI);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(closeUiReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(closeUiReceiver, filter);
        }
    }

    private void closeUiAndReturnHome() {
        try {
            Intent home = new Intent(Intent.ACTION_MAIN);
            home.addCategory(Intent.CATEGORY_HOME);
            home.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(home);
        } catch (Throwable ignored) {
        }
        try {
            finishAffinity();
        } catch (Throwable ignored) {
        }
        try {
            finishAndRemoveTask();
        } catch (Throwable ignored) {
        }
    }

    private String buildEndpointText() {
        String ip = getLikelyIpv4Address();
        if (ip == null) {
            ip = "device-ip";
        }
        return "HTTP API base:\nhttp://" + ip + ":9124/\n\n"
                + "Examples:\n"
                + "http://" + ip + ":9124/get-hardware-stats\n"
                + "http://" + ip + ":9124/get-wifi-stats\n"
                + "http://" + ip + ":9124/get-results";
    }

    private String getLikelyIpv4Address() {
        try {
            WifiManager wifi = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            if (wifi != null && wifi.getConnectionInfo() != null) {
                int ip = wifi.getConnectionInfo().getIpAddress();
                if (ip != 0) {
                    return (ip & 0xff) + "." + ((ip >> 8) & 0xff) + "."
                            + ((ip >> 16) & 0xff) + "." + ((ip >> 24) & 0xff);
                }
            }
        } catch (Throwable ignored) {
        }

        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            for (NetworkInterface nif : Collections.list(interfaces)) {
                if (!nif.isUp() || nif.isLoopback()) {
                    continue;
                }
                for (java.net.InetAddress addr : Collections.list(nif.getInetAddresses())) {
                    if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                        return addr.getHostAddress();
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }
}
