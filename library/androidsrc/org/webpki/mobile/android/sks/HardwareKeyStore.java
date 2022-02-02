/*
 *  Copyright 2006-2019 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.mobile.android.sks;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import java.security.interfaces.RSAKey;

import java.security.spec.ECGenParameterSpec;
import java.security.spec.AlgorithmParameterSpec;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;

import javax.security.auth.x500.X500Principal;

import org.webpki.sks.SKSException;

import android.util.Log;

import android.os.Build;

import android.content.Context;

import android.provider.Settings;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;

// This class holds all interfaces between SKS and the AndroidKeyStore.
// It also provides SKS/AndroidKeyStore initialization and serialization support. 

public abstract class HardwareKeyStore {

    private static final String PERSISTENCE_SKS   = "SKS";  // SKS persistence file

    private static final String DEVICE_KEY_NAME   = "device";

    private static final String LOG_NAME          = "ANDROID/KS";

    private static final String ANDROID_KEYSTORE  = "AndroidKeyStore";    // Hardware backed keys


    private static AndroidSKSImplementation sks;

    private static HashSet<String> supportedAlgorithms;

    private static KeyStore hardwareBacked;

    static {
        try {
            hardwareBacked = KeyStore.getInstance(ANDROID_KEYSTORE);
            hardwareBacked.load(null);
        } catch (Exception e) {
            Log.e(LOG_NAME, e.getMessage());
            throw new RuntimeException();
        }
    }

    private static X509Certificate[] deviceCertificatePath;
    private static PrivateKey deviceKey;

    static void getDeviceCredentials(String androidId) {
        if (deviceCertificatePath == null) {
            try {
                if (hardwareBacked.isKeyEntry(DEVICE_KEY_NAME)) {
                    deviceKey = (PrivateKey) hardwareBacked.getKey(DEVICE_KEY_NAME, null);
                    Log.i(LOG_NAME, "Had a key already");
                } else {
                    byte[] serial = new byte[8];
                    new SecureRandom().nextBytes(serial);
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                            KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);
                    KeyGenParameterSpec.Builder builder =
                    new KeyGenParameterSpec.Builder(
                            DEVICE_KEY_NAME, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                            .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setCertificateSerialNumber(new BigInteger(1, serial))
                            .setCertificateNotBefore(new Date(System.currentTimeMillis() - 600000L))
                            .setCertificateSubject(new X500Principal("serialNumber=" +
                                    (androidId == null ? "N/A" : androidId) + ",CN=Android SKS"));
                    if (Build.VERSION.SDK_INT > 24) {
                        // Some Android 7 devices seem awfully broken...
                        builder.setAttestationChallenge("webpki.org".getBytes("utf-8"));
                    }
                    kpg.initialize(builder.build());
                    KeyPair keyPair = kpg.generateKeyPair();
                    deviceKey = keyPair.getPrivate();
                    Log.i(LOG_NAME, "Created a key");
                }
                ArrayList<X509Certificate> certPath = new ArrayList<>();
                for (Certificate certificate : hardwareBacked.getCertificateChain(DEVICE_KEY_NAME)) {
                    // Older Androids are severely broken and have "holes" in the certificate chain...
                    if (!certPath.isEmpty() && !certPath.get(certPath.size() - 1)
                            .getIssuerX500Principal().toString().equals(
                                    ((X509Certificate)certificate)
                                            .getSubjectX500Principal().toString())) {
                        break;
                    }
                    certPath.add((X509Certificate)certificate);
                }
                deviceCertificatePath = certPath.toArray(new X509Certificate[0]);
            } catch (Exception e) {
                Log.e(LOG_NAME, e.getMessage());
            }
        }
    }

    public static synchronized AndroidSKSImplementation createSKS(String callerForLog,
                                                                  Context caller,
                                                                  boolean saveIfNew) {
        getDeviceCredentials(Settings.Secure.getString(caller.getContentResolver(),
                             Settings.Secure.ANDROID_ID));
        if (sks == null) {
            try {
                sks = (AndroidSKSImplementation) new ObjectInputStream(
                        caller.openFileInput(PERSISTENCE_SKS)).readObject();
                getAlgorithms();
                Log.i(callerForLog, "SKS found, restoring it");
            } catch (Exception e) {
                Log.i(callerForLog, "SKS not found, recreating it");
                try {
                    sks = new AndroidSKSImplementation();
                    if (saveIfNew) {
                        serializeSKS(callerForLog, caller);
                    }
                    getAlgorithms();
                } catch (Exception e2) {
                    Log.e(callerForLog, e2.getMessage());
                }
            }
            sks.setDeviceCredentials(deviceCertificatePath, deviceKey);
        }
        return sks;
    }

    private static void getAlgorithms() throws SKSException {
        supportedAlgorithms = new HashSet<>();
        for (String alg : sks.getDeviceInfo().getSupportedAlgorithms()) {
            supportedAlgorithms.add(alg);
        }
    }

    static PublicKey createSecureKeyPair(String keyId, 
                                         AlgorithmParameterSpec algParSpec,
                                         boolean rsaFlag) throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(rsaFlag ? 
                                    KeyProperties.KEY_ALGORITHM_RSA : KeyProperties.KEY_ALGORITHM_EC, 
                                                            ANDROID_KEYSTORE);
        KeyGenParameterSpec.Builder builder = 
            new KeyGenParameterSpec.Builder(keyId,
                    KeyProperties.PURPOSE_SIGN | (rsaFlag ?  KeyProperties.PURPOSE_DECRYPT : 0))
                .setAlgorithmParameterSpec(algParSpec)
                .setDigests(KeyProperties.DIGEST_NONE,
                            KeyProperties.DIGEST_SHA256,
                            KeyProperties.DIGEST_SHA384,
                            KeyProperties.DIGEST_SHA512);
        if (rsaFlag) {
            builder.setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                   .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1,
                                          KeyProperties.ENCRYPTION_PADDING_RSA_OAEP);
        }
        kpg.initialize(builder.build());
        return kpg.generateKeyPair().getPublic();
    }

    public static synchronized void serializeSKS(String callerForLog, Context caller) {
        if (sks != null) {
            try {
                ObjectOutputStream oos = new ObjectOutputStream(caller.openFileOutput(PERSISTENCE_SKS, Context.MODE_PRIVATE));
                oos.writeObject(sks);
                oos.close();
                Log.i(callerForLog, "Successfully wrote SKS");
            } catch (Exception e) {
                Log.e(callerForLog, "Couldn't write SKS: " + e.getMessage());
            }
        }
    }
    
    static void importKey(String keyId, 
                          PrivateKey privateKey, 
                          X509Certificate[] certificatePath) throws GeneralSecurityException {
        boolean rsaFlag = privateKey instanceof RSAKey;
        KeyProtection.Builder builder =
            new KeyProtection.Builder(KeyProperties.PURPOSE_SIGN |
                                      (rsaFlag ?  KeyProperties.PURPOSE_DECRYPT : 0))
                .setDigests(KeyProperties.DIGEST_NONE);
        if (rsaFlag) {
            builder.setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                   .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1,
                                          KeyProperties.ENCRYPTION_PADDING_RSA_OAEP);
        }
        hardwareBacked.setEntry(keyId,
                                new KeyStore.PrivateKeyEntry(privateKey, certificatePath),
                                builder.build());

    }

    static void deleteKey(String keyId) throws GeneralSecurityException {
        hardwareBacked.deleteEntry(keyId);
    }

    static PrivateKey getPrivateKey(String keyId) throws GeneralSecurityException {
        return (PrivateKey)hardwareBacked.getKey(keyId, null);
    }

    public static boolean isSupported(String algorithm) {
        return supportedAlgorithms.contains(algorithm);
    }
}
