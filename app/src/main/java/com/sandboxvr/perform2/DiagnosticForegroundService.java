package com.sandboxvr.perform2;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

import alvr.client.DiagnosticManager;

public class DiagnosticForegroundService extends Service {
    public static final String ACTION_START = "com.sandboxvr.perform2.action.START";
    public static final String ACTION_STOP = "com.sandboxvr.perform2.action.STOP";
    private static final String CHANNEL_ID = "diag_background";
    private static final int NOTIFICATION_ID = 1001;

    public static void start(Context context) {
        Intent intent = new Intent(context, DiagnosticForegroundService.class);
        intent.setAction(ACTION_START);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent);
        } else {
            context.startService(intent);
        }
    }

    public static void stop(Context context) {
        Intent intent = new Intent(context, DiagnosticForegroundService.class);
        intent.setAction(ACTION_STOP);
        context.startService(intent);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent != null ? intent.getAction() : ACTION_START;
        if (ACTION_STOP.equals(action)) {
            DiagnosticManager.stop();
            stopForeground(true);
            stopSelf();
            return START_NOT_STICKY;
        }

        createNotificationChannel();
        startForeground(NOTIFICATION_ID, buildNotification());
        DiagnosticManager.start(getApplicationContext());
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        DiagnosticManager.stop();
        super.onDestroy();
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private Notification buildNotification() {
        Intent openApp = new Intent(this, MainActivity.class);
        PendingIntent contentIntent = PendingIntent.getActivity(
                this,
                0,
                openApp,
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
                        ? PendingIntent.FLAG_IMMUTABLE
                        : 0
        );

        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle(getString(R.string.notification_title))
                .setContentText(getString(R.string.notification_text))
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentIntent(contentIntent)
                .setOngoing(true)
                .build();
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return;
        }
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null || nm.getNotificationChannel(CHANNEL_ID) != null) {
            return;
        }
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW
        );
        nm.createNotificationChannel(channel);
    }
}
