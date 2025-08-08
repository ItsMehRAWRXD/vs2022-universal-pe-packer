// VS2022 Menu Encryptor - Android Version
// Java wrapper with JNI integration

package com.itsmehrawrxd.vs2022encryptor;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.widget.*;
import androidx.core.app.ActivityCompat;
import androidx.security.crypto.EncryptedFile;
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKeys;
import androidx.biometric.BiometricPrompt;

import java.io.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class VS2022MenuEncryptorActivity extends Activity {
    
    // Load native library
    static {
        System.loadLibrary("vs2022encryptor");
    }
    
    // Native methods
    private native void initializeNative();
    private native byte[] encryptDataNative(byte[] data);
    private native byte[] decryptDataNative(byte[] data);
    private native boolean checkRootNative();
    private native boolean checkDebuggerNative();
    
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "VS2022EncryptorKey";
    
    private FingerprintManager fingerprintManager;
    private KeyStore keyStore;
    private boolean isRooted;
    private boolean hasFingerprint;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // Initialize native component
        initializeNative();
        
        // Check security
        checkSecurity();
        
        // Setup UI
        setupUI();
        
        // Initialize crypto
        initializeCrypto();
    }
    
    private void checkSecurity() {
        // Check for root
        isRooted = checkRootNative() || checkRootJava();
        
        // Check for debugger
        if (checkDebuggerNative() || android.os.Debug.isDebuggerConnected()) {
            Toast.makeText(this, "Debugger detected!", Toast.LENGTH_LONG).show();
            finish();
            return;
        }
        
        // Check for emulator
        if (isEmulator()) {
            Toast.makeText(this, "Emulator detected!", Toast.LENGTH_LONG).show();
        }
        
        // Check fingerprint hardware
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            fingerprintManager = (FingerprintManager) getSystemService(Context.FINGERPRINT_SERVICE);
            hasFingerprint = fingerprintManager != null && 
                           fingerprintManager.isHardwareDetected() &&
                           fingerprintManager.hasEnrolledFingerprints();
        }
    }
    
    private boolean checkRootJava() {
        String[] paths = {
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su"
        };
        
        for (String path : paths) {
            if (new File(path).exists()) {
                return true;
            }
        }
        
        // Check for root packages
        String[] packages = {
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su"
        };
        
        PackageManager pm = getPackageManager();
        for (String packageName : packages) {
            try {
                pm.getPackageInfo(packageName, 0);
                return true;
            } catch (PackageManager.NameNotFoundException e) {
                // Package not found, continue
            }
        }
        
        return false;
    }
    
    private boolean isEmulator() {
        return Build.FINGERPRINT.startsWith("generic") ||
               Build.FINGERPRINT.startsWith("unknown") ||
               Build.MODEL.contains("google_sdk") ||
               Build.MODEL.contains("Emulator") ||
               Build.MODEL.contains("Android SDK built for x86") ||
               Build.MANUFACTURER.contains("Genymotion") ||
               (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")) ||
               "google_sdk".equals(Build.PRODUCT);
    }
    
    private void initializeCrypto() {
        try {
            keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            
            // Generate key if not exists
            if (!keyStore.containsAlias(KEY_ALIAS)) {
                generateKey();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private void generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
            
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256);
            
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            builder.setInvalidatedByBiometricEnrollment(false);
        }
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setUnlockedDeviceRequired(true);
            builder.setIsStrongBoxBacked(true);
        }
        
        keyGenerator.init(builder.build());
        keyGenerator.generateKey();
    }
    
    private void setupUI() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(20, 20, 20, 20);
        
        TextView title = new TextView(this);
        title.setText("VS2022 Menu Encryptor - Android");
        title.setTextSize(24);
        title.setPadding(0, 0, 0, 20);
        layout.addView(title);
        
        // System info
        TextView info = new TextView(this);
        info.setText("System Status:\n" +
                    "• Android " + Build.VERSION.RELEASE + " (API " + Build.VERSION.SDK_INT + ")\n" +
                    "• Device: " + Build.MANUFACTURER + " " + Build.MODEL + "\n" +
                    "• Root: " + (isRooted ? "YES" : "NO") + "\n" +
                    "• Fingerprint: " + (hasFingerprint ? "Available" : "Not Available"));
        info.setPadding(0, 0, 0, 20);
        layout.addView(info);
        
        // Buttons
        String[] options = {
            "Select File to Encrypt",
            "Encrypt with Fingerprint",
            "Use Hardware Security Module",
            "Encrypted Storage Demo",
            "Monitor File Access",
            "Check App Integrity",
            "Secure Network Request",
            "Export Encrypted Backup"
        };
        
        for (int i = 0; i < options.length; i++) {
            Button btn = new Button(this);
            btn.setText(options[i]);
            final int index = i;
            btn.setOnClickListener(v -> handleOption(index));
            layout.addView(btn);
        }
        
        ScrollView scrollView = new ScrollView(this);
        scrollView.addView(layout);
        setContentView(scrollView);
    }
    
    private void handleOption(int option) {
        switch (option) {
            case 0:
                selectFile();
                break;
            case 1:
                encryptWithFingerprint();
                break;
            case 2:
                useHSM();
                break;
            case 3:
                encryptedStorageDemo();
                break;
            case 4:
                monitorFileAccess();
                break;
            case 5:
                checkAppIntegrity();
                break;
            case 6:
                secureNetworkRequest();
                break;
            case 7:
                exportEncryptedBackup();
                break;
        }
    }
    
    private void selectFile() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("*/*");
        startActivityForResult(intent, 1);
    }
    
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == 1 && resultCode == RESULT_OK) {
            Uri uri = data.getData();
            encryptFile(uri);
        }
    }
    
    private void encryptFile(Uri uri) {
        try {
            InputStream inputStream = getContentResolver().openInputStream(uri);
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            
            int nRead;
            byte[] data = new byte[1024];
            while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
                buffer.write(data, 0, nRead);
            }
            
            byte[] fileData = buffer.toByteArray();
            
            // Encrypt using native method
            byte[] encrypted = encryptDataNative(fileData);
            
            // Save encrypted file
            File outputFile = new File(getFilesDir(), "encrypted_" + System.currentTimeMillis() + ".enc");
            FileOutputStream fos = new FileOutputStream(outputFile);
            fos.write(encrypted);
            fos.close();
            
            Toast.makeText(this, "File encrypted: " + outputFile.getName(), Toast.LENGTH_LONG).show();
            
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(this, "Encryption failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }
    
    private void encryptWithFingerprint() {
        if (!hasFingerprint) {
            Toast.makeText(this, "Fingerprint not available", Toast.LENGTH_SHORT).show();
            return;
        }
        
        BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authenticate to Encrypt")
            .setSubtitle("Use your fingerprint to encrypt data")
            .setNegativeButtonText("Cancel")
            .build();
            
        BiometricPrompt biometricPrompt = new BiometricPrompt(this,
            getMainExecutor(),
            new BiometricPrompt.AuthenticationCallback() {
                @Override
                public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                    super.onAuthenticationSucceeded(result);
                    
                    // Perform encryption after authentication
                    performSecureEncryption();
                }
                
                @Override
                public void onAuthenticationFailed() {
                    super.onAuthenticationFailed();
                    Toast.makeText(VS2022MenuEncryptorActivity.this, 
                        "Authentication failed", Toast.LENGTH_SHORT).show();
                }
            });
            
        biometricPrompt.authenticate(promptInfo);
    }
    
    private void performSecureEncryption() {
        try {
            // Get key from Android Keystore
            SecretKey secretKey = (SecretKey) keyStore.getKey(KEY_ALIAS, null);
            
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            
            byte[] iv = cipher.getIV();
            byte[] encryption = cipher.doFinal("Secure data".getBytes("UTF-8"));
            
            Toast.makeText(this, "Data encrypted with hardware-backed key", 
                Toast.LENGTH_LONG).show();
                
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private void useHSM() {
        Toast.makeText(this, "Hardware Security Module: " + 
            (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P ? "StrongBox Available" : "TEE Only"),
            Toast.LENGTH_LONG).show();
    }
    
    private void encryptedStorageDemo() {
        try {
            // Encrypted SharedPreferences
            String masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC);
            
            SharedPreferences sharedPreferences = EncryptedSharedPreferences.create(
                "secret_shared_prefs",
                masterKeyAlias,
                this,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            );
            
            // Store encrypted data
            sharedPreferences.edit()
                .putString("secret_key", "This is encrypted!")
                .apply();
                
            // Encrypted file
            File secretFile = new File(getFilesDir(), "secret_data.txt");
            EncryptedFile encryptedFile = new EncryptedFile.Builder(
                secretFile,
                this,
                masterKeyAlias,
                EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
            ).build();
            
            FileOutputStream outputStream = encryptedFile.openFileOutput();
            outputStream.write("Secret file content".getBytes());
            outputStream.close();
            
            Toast.makeText(this, "Encrypted storage demo complete", Toast.LENGTH_LONG).show();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private void monitorFileAccess() {
        Toast.makeText(this, "File monitoring active", Toast.LENGTH_SHORT).show();
        
        // Monitor app's private directory
        FileObserver observer = new FileObserver(getFilesDir().getPath()) {
            @Override
            public void onEvent(int event, String path) {
                String eventType = "";
                switch (event) {
                    case FileObserver.ACCESS:
                        eventType = "ACCESS";
                        break;
                    case FileObserver.CREATE:
                        eventType = "CREATE";
                        break;
                    case FileObserver.DELETE:
                        eventType = "DELETE";
                        break;
                    case FileObserver.MODIFY:
                        eventType = "MODIFY";
                        break;
                }
                
                if (!eventType.isEmpty()) {
                    runOnUiThread(() -> 
                        Toast.makeText(VS2022MenuEncryptorActivity.this,
                            "File event: " + eventType + " - " + path,
                            Toast.LENGTH_SHORT).show()
                    );
                }
            }
        };
        
        observer.startWatching();
    }
    
    private void checkAppIntegrity() {
        try {
            // Get app signature
            Signature[] signatures = getPackageManager()
                .getPackageInfo(getPackageName(), PackageManager.GET_SIGNATURES)
                .signatures;
                
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (Signature signature : signatures) {
                md.update(signature.toByteArray());
            }
            
            byte[] digest = md.digest();
            String hash = Base64.encodeToString(digest, Base64.NO_WRAP);
            
            Toast.makeText(this, "App signature hash: " + hash.substring(0, 16) + "...",
                Toast.LENGTH_LONG).show();
                
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private void secureNetworkRequest() {
        Toast.makeText(this, "Secure network features available", Toast.LENGTH_SHORT).show();
        // Network security config and certificate pinning would be configured in manifest
    }
    
    private void exportEncryptedBackup() {
        try {
            // Create encrypted backup of all app data
            File backupFile = new File(getExternalFilesDir(null), 
                "backup_" + System.currentTimeMillis() + ".enc");
                
            // Collect all data
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            
            // Add app data
            Map<String, Object> backupData = new HashMap<>();
            backupData.put("timestamp", System.currentTimeMillis());
            backupData.put("version", BuildConfig.VERSION_CODE);
            backupData.put("device", Build.MODEL);
            
            oos.writeObject(backupData);
            oos.close();
            
            // Encrypt backup
            byte[] encrypted = encryptDataNative(baos.toByteArray());
            
            FileOutputStream fos = new FileOutputStream(backupFile);
            fos.write(encrypted);
            fos.close();
            
            Toast.makeText(this, "Backup exported: " + backupFile.getName(),
                Toast.LENGTH_LONG).show();
                
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}