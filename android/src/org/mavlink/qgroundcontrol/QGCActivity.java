package org.mavlink.qgroundcontrol;

import java.io.File;
import java.util.List;
import java.lang.reflect.Method;
import java.io.FileOutputStream;
import java.io.InputStream;

import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.PowerManager;
import android.net.wifi.WifiManager;
import android.provider.OpenableColumns;
import android.provider.Settings;
import android.util.Log;
import android.view.WindowManager;
import android.app.Activity;
import android.os.storage.StorageManager;
import android.os.storage.StorageVolume;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import org.qtproject.qt.android.bindings.QtActivity;

public class QGCActivity extends QtActivity {
    private static final String TAG = QGCActivity.class.getSimpleName();
    private static final String SCREEN_BRIGHT_WAKE_LOCK_TAG = "QGroundControl";
    private static final String MULTICAST_LOCK_TAG = "QGroundControl";

    private static QGCActivity m_instance = null;

    private PowerManager.WakeLock m_wakeLock;
    private WifiManager.MulticastLock m_wifiMulticastLock;

    private static final int IMPORT_FILE_REQUEST_CODE = 42;
    private static String s_importDestPath = "";
    private static String s_importFilename = "";
    private static String[] s_allowedExtensions = new String[0];

    public QGCActivity() {
        m_instance = this;
    }

    /**
     * Returns the singleton instance of QGCActivity.
     *
     * @return The current instance of QGCActivity.
     */
    public static QGCActivity getInstance() {
        return m_instance;
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        nativeInit();
        acquireWakeLock();
        keepScreenOn();
        setupMulticastLock();

        QGCUsbSerialManager.initialize(this);
    }

    @Override
    protected void onDestroy() {
        try {
            releaseMulticastLock();
            releaseWakeLock();
            QGCUsbSerialManager.cleanup(this);
        } catch (final Exception e) {
            Log.e(TAG, "Exception onDestroy()", e);
        }

        super.onDestroy();
    }

    /**
     * Validates that a filename has one of the allowed extensions.
     * 
     * @param displayName           The filename to validate
     * @param allowedExtensions     Array of allowed extensions (e.g., {".crt", ".pem", ".cer"})
     * @return true if filename ends with one of the allowed extensions
     */
    public static boolean isValidCertFileName(final String displayName, final String[] allowedExtensions) {
        if (displayName == null || displayName.isEmpty()) {
            return false;
        }
    
        if (allowedExtensions == null || allowedExtensions.length == 0) {
            return false;
        }
    
        String lower = displayName.toLowerCase(java.util.Locale.ROOT);
        for (String ext : allowedExtensions) {
            if (lower.endsWith(ext.toLowerCase(java.util.Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Helper: Extract display name from Content URI
     */
    private String extractDisplayName(final Uri uri) {
        String displayName = "";
        try (Cursor cursor = getContentResolver().query(uri, null, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                final int nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (nameIndex >= 0) {
                    displayName = cursor.getString(nameIndex);
                }
            }
        } catch (Exception e) {
            QGCLogger.e(TAG, "Failed to query display name", e);
        }
        return displayName;
    }
    
    /**
     * Copies a file identified by a content URI to the specified destination directory with a fixed filename.
     *
     * @param uri       Content URI of the source file
     * @param destDir   Fully-qualified path of the destination directory
     * @param filename  Fixed filename (will overwrite if exists)
     * @return Fully-qualified path of the copied file, or null on failure
     */
    private String copyFileToDestination(final Uri uri, final String destDir, final String filename) {
        if (destDir == null || destDir.isEmpty()) {
            QGCLogger.e(TAG, "copyFileToDestination: destination directory is empty");
            return null;
        }
    
        if (filename == null || filename.isEmpty()) {
            QGCLogger.e(TAG, "copyFileToDestination: filename is empty");
            return null;
        }
    
        final File destDirectory = new File(destDir);
        if (!destDirectory.exists()) {
            QGCLogger.e(TAG, "Destination directory does not exist: " + destDir);
            return null;
        }
    
        // Save File Fixed name(override)
        final File destFile = new File(destDirectory, filename);
    
        try (InputStream is = getContentResolver().openInputStream(uri);
            FileOutputStream fos = new FileOutputStream(destFile)) {
        
            if (is == null) {
                QGCLogger.e(TAG, "Failed to open input stream for URI: " + uri);
                return null;
            }
        
            final byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = is.read(buffer)) != -1) {
                fos.write(buffer, 0, bytesRead);
            }
        
            QGCLogger.i(TAG, "File imported successfully to: " + destFile.getAbsolutePath());
            return destFile.getAbsolutePath();
        
        } catch (Exception e) {
            QGCLogger.e(TAG, "Failed to copy file to destination", e);
            return null;
        }
    }

    /**
     * Opens Android's native file picker using ACTION_OPEN_DOCUMENT.
     * The selected file will be copied to the provided destination directory if it has an allowed extension.
     *
     * @param destPath              Fully-qualified path of the destination directory
     * @param filename              Fixed filename for the copied file (will overwrite if exists)
     * @param allowedExtensions     Array of allowed file extensions (e.g., {".crt", ".pem", ".cer"})
     */
    public static void openFileImportDialog(final String destPath, final String filename, final String[] allowedExtensions) {
        if (m_instance == null) {
            QGCLogger.e(TAG, "Activity instance is null");
            return;
        }
    
        s_importDestPath = (destPath != null) ? destPath : "";
        s_importFilename = (filename != null) ? filename : "";
        s_allowedExtensions = (allowedExtensions != null) ? allowedExtensions : new String[0];
    
        m_instance.runOnUiThread(() -> {
            final Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.setType("*/*");
            m_instance.startActivityForResult(intent, IMPORT_FILE_REQUEST_CODE);
        });
    }
    
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == IMPORT_FILE_REQUEST_CODE) {
            if (resultCode == RESULT_OK && data != null) {
                final Uri uri = data.getData();
                if (uri != null) {
                    // Check file extension
                    final String displayName = extractDisplayName(uri);
                    if (!isValidCertFileName(displayName, s_allowedExtensions)) {
                        QGCLogger.w(TAG, "onActivityResult: file extension not allowed. File: " + displayName);
                        onPQCImportResult("");
                        return;
                    }
                
                    final String importedPath = copyFileToDestination(uri, s_importDestPath, s_importFilename);
                    onPQCImportResult(importedPath != null ? importedPath : "");
                } else {
                    QGCLogger.w(TAG, "onActivityResult: null URI for file import");
                    onPQCImportResult("");
                }
            } else {
                QGCLogger.i(TAG, "onActivityResult: file import cancelled or no data returned");
                onPQCImportResult("");
            }
            return;
        }
        super.onActivityResult(requestCode, resultCode, data);
    }
    public native void onPQCImportResult(final String filePath);

    /**
     * Keeps the screen on by adding the appropriate window flag.
     */
    private void keepScreenOn() {
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
    }

    /**
     * Acquires a wake lock to keep the CPU running.
     */
    private void acquireWakeLock() {
        final PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
        m_wakeLock = pm.newWakeLock(PowerManager.SCREEN_BRIGHT_WAKE_LOCK, SCREEN_BRIGHT_WAKE_LOCK_TAG);
        if (m_wakeLock != null) {
            m_wakeLock.acquire();
        } else {
            Log.w(TAG, "SCREEN_BRIGHT_WAKE_LOCK not acquired!");
        }
    }

    /**
     * Releases the wake lock if held.
     */
    private void releaseWakeLock() {
        if (m_wakeLock != null && m_wakeLock.isHeld()) {
            m_wakeLock.release();
        }
    }

    /**
     * Sets up a multicast lock to allow multicast packets.
     */
    private void setupMulticastLock() {
        if (m_wifiMulticastLock == null) {
            final WifiManager wifi = (WifiManager) getSystemService(Context.WIFI_SERVICE);
            m_wifiMulticastLock = wifi.createMulticastLock(MULTICAST_LOCK_TAG);
            m_wifiMulticastLock.setReferenceCounted(true);
        }

        m_wifiMulticastLock.acquire();
        Log.d(TAG, "Multicast lock: " + m_wifiMulticastLock.toString());
    }

    /**
     * Releases the multicast lock if held.
     */
    private void releaseMulticastLock() {
        if (m_wifiMulticastLock != null && m_wifiMulticastLock.isHeld()) {
            m_wifiMulticastLock.release();
            Log.d(TAG, "Multicast lock released.");
        }
    }

    public static String getSDCardPath() {
        StorageManager storageManager = (StorageManager)m_instance.getSystemService(Activity.STORAGE_SERVICE);
        List<StorageVolume> volumes = storageManager.getStorageVolumes();
        
        for (StorageVolume vol : volumes) {
            if (!vol.isRemovable()) {
                continue;
            }
            
            String path = null;
            
            // For Android 11+ (API 30+), use the proper getDirectory() method
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                File directory = vol.getDirectory();
                if (directory != null) {
                    path = directory.getAbsolutePath();
                }
            } else {
                // For older versions, use reflection to get the path
                try {
                    Method mMethodGetPath = vol.getClass().getMethod("getPath");
                    path = (String) mMethodGetPath.invoke(vol);
                } catch (Exception e) {
                    Log.e(TAG, "Failed to get path via reflection", e);
                    continue;
                }
            }
            
            if (path != null && !path.isEmpty()) {
                Log.i(TAG, "removable sd card mounted at " + path);
                return path;
            }
        }
        
        Log.w(TAG, "No removable SD card found");
        return "";
    }

    /**
     * Checks and requests storage permissions for SD card access.
     * For Android 11+ (API 30+), this requires MANAGE_EXTERNAL_STORAGE permission.
     *
     * @return true if permissions are granted, false otherwise
     */
    public static boolean checkStoragePermissions() {
        if (m_instance == null) {
            Log.e(TAG, "Activity instance is null");
            return false;
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // Android 11+ (API 30+) requires MANAGE_EXTERNAL_STORAGE for full SD card access
            if (!Environment.isExternalStorageManager()) {
                Log.i(TAG, "MANAGE_EXTERNAL_STORAGE not granted, requesting...");
                try {
                    Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                    intent.setData(Uri.parse("package:" + m_instance.getPackageName()));
                    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    m_instance.startActivity(intent);
                } catch (Exception e) {
                    Log.e(TAG, "Failed to open storage permission settings", e);
                    // Fallback to general settings
                    Intent intent = new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION);
                    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    m_instance.startActivity(intent);
                }
                return false;
            }
            Log.i(TAG, "MANAGE_EXTERNAL_STORAGE already granted");
            return true;
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            // Android 6.0+ (API 23+) requires runtime permissions
            String[] permissions = {
                android.Manifest.permission.READ_EXTERNAL_STORAGE,
                android.Manifest.permission.WRITE_EXTERNAL_STORAGE
            };

            boolean allGranted = true;
            for (String permission : permissions) {
                if (ContextCompat.checkSelfPermission(m_instance, permission) != PackageManager.PERMISSION_GRANTED) {
                    allGranted = false;
                    break;
                }
            }

            if (!allGranted) {
                Log.i(TAG, "Storage permissions not granted, requesting...");
                ActivityCompat.requestPermissions(m_instance, permissions, 1);
                return false;
            }

            Log.i(TAG, "Storage permissions already granted");
            return true;
        } else {
            // Below Android 6.0, permissions are granted at install time
            return true;
        }
    }

    // Native C++ functions
    public native boolean nativeInit();
    public native void qgcLogDebug(final String message);
    public native void qgcLogWarning(final String message);
}
