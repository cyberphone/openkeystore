/*
 *  Copyright 2006-2018 WebPKI.org (http://webpki.org).
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
package org.webpki.sks;

import java.io.IOException;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import java.security.interfaces.RSAPublicKey;

import java.util.EnumSet;
import java.util.Enumeration;
import java.util.Vector;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymEncryptionAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.KeyStoreReader;

import org.webpki.sks.AppUsage;
import org.webpki.sks.BiometricProtection;
import org.webpki.sks.DeleteProtection;
import org.webpki.sks.EnumeratedKey;
import org.webpki.sks.EnumeratedProvisioningSession;
import org.webpki.sks.ExportProtection;
import org.webpki.sks.Grouping;
import org.webpki.sks.InputMethod;
import org.webpki.sks.PassphraseFormat;
import org.webpki.sks.PatternRestriction;
import org.webpki.sks.SecureKeyStore;

import org.webpki.sks.ws.WSSpecific;

public class PKCS12Import {
    public static void main(String[] argc) throws Exception {
        if (argc.length != 2 && argc.length != 8) {
            System.out.println("\nUsage: " + PKCS12Import.class.getCanonicalName() +
                    " file password [pin format imputmethod grouping appusage pincaching]");
            System.exit(-3);
        }
        String pin_value = null;
        AppUsage appUsage = AppUsage.UNIVERSAL;
        PassphraseFormat format = null;
        InputMethod inputMethod = null;
        Grouping grouping = null;
        String[] endorsed_algs = new String[0];
        boolean pin_caching = false;
        if (argc.length > 2) {
            pin_value = argc[2];
            format = PassphraseFormat.valueOf(argc[3]);
            inputMethod = InputMethod.valueOf(argc[4]);
            grouping = Grouping.valueOf(argc[5]);
            appUsage = AppUsage.valueOf(argc[6]);
            pin_caching = new Boolean(argc[7]);
        }
        CustomCryptoProvider.forcedLoad(true);
        KeyStore ks = KeyStoreReader.loadKeyStore(argc[0], argc[1]);
        Vector<X509Certificate> cert_path = new Vector<X509Certificate>();
        PrivateKey privateKey = null;
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.isKeyEntry(alias)) {
                privateKey = (PrivateKey) ks.getKey(alias, argc[1].toCharArray());
                for (Certificate cert : ks.getCertificateChain(alias)) {
                    cert_path.add((X509Certificate) cert);
                }
                break;
            }
        }
        boolean rsaFlag = cert_path.firstElement().getPublicKey() instanceof RSAPublicKey;
        if (privateKey == null) {
            throw new IOException("No private key!");
        }
        if (appUsage == AppUsage.ENCRYPTION) {
            endorsed_algs = rsaFlag ?
                    new String[]{AsymEncryptionAlgorithms.RSA_ES_PKCS_1_5.getAlgorithmId(AlgorithmPreferences.SKS),
                            AsymEncryptionAlgorithms.RSA_OAEP_SHA1_MGF1P.getAlgorithmId(AlgorithmPreferences.SKS),
                            AsymEncryptionAlgorithms.RSA_OAEP_SHA256_MGF1P.getAlgorithmId(AlgorithmPreferences.SKS)}
                    :
                    new String[]{SecureKeyStore.ALGORITHM_ECDH_RAW};
        } else if (appUsage == AppUsage.SIGNATURE) {
            endorsed_algs = rsaFlag ?
                    new String[]{AsymSignatureAlgorithms.RSA_SHA1.getAlgorithmId(AlgorithmPreferences.SKS), AsymSignatureAlgorithms.RSA_SHA256.getAlgorithmId(AlgorithmPreferences.SKS)}
                    :
                    new String[]{AsymSignatureAlgorithms.ECDSA_SHA256.getAlgorithmId(AlgorithmPreferences.SKS)};
        }
        SecureKeyStore sks = (SecureKeyStore) Class.forName(System.getProperty("sks.client")).newInstance();
        EnumeratedKey ek = new EnumeratedKey();
        GenKey oldKey = null;
        while ((ek = sks.enumerateKeys(ek.getKeyHandle())) != null) {
            if (sks.getKeyAttributes(ek.getKeyHandle()).getCertificatePath()[0].equals(cert_path.get(0))) {
                System.out.println("Duplicate entry - Replace key #" + ek.getKeyHandle());
                EnumeratedProvisioningSession eps = new EnumeratedProvisioningSession();
                while ((eps = sks.enumerateProvisioningSessions(eps.getProvisioningHandle(), false)) != null) {
                    if (eps.getProvisioningHandle() == ek.getProvisioningHandle()) {
                        PublicKey kmk = eps.getKeyManagementKey();
                        if (kmk != null && new ProvSess.SoftHSM().enumerateKeyManagementKeys()[0].equals(kmk)) {
                            oldKey = new GenKey();
                            oldKey.keyHandle = ek.getKeyHandle();
                            oldKey.cert_path = cert_path.toArray(new X509Certificate[0]);
                            if (sks instanceof WSSpecific) {
                                ((WSSpecific) sks).logEvent("Updating");
                            }
                        }
                        break;
                    }
                }
                break;
            }
        }
        Device device = new Device(sks);
        ProvSess sess = new ProvSess(device, 0);
        if (oldKey != null) {
            sess.postDeleteKey(oldKey);
        }
        PINPol pinPolicy = null;
        String prot = "NO PIN";
        if (argc.length > 2) {
            pin_value = argc[2];
            sess.setInputMethod(inputMethod);
            prot = "PIN [Format=" + format + ", InputMode=" + inputMethod + ", Grouping=" + grouping +
                    ", AppUsage=" + appUsage + ", PINCaching=" + pin_caching + "]";
            pinPolicy = sess.createPINPolicy("PIN",
                    format,
                    EnumSet.noneOf(PatternRestriction.class),
                    grouping,
                    1 /* minLength */,
                    50 /* maxLength */,
                    (short) 3 /* retryLimit*/,
                    null /* pukPolicy */);
        }
        GenKey key = sess.createKey("Key",
                SecureKeyStore.ALGORITHM_KEY_ATTEST_1,
                null /* serverSeed */,
                pinPolicy,
                pin_value,
                BiometricProtection.NONE /* biometricProtection */,
                ExportProtection.NON_EXPORTABLE /* export_policy */,
                DeleteProtection.NONE /* delete_policy */,
                pin_caching /* enablePinCaching */,
                appUsage,
                "" /* friendlyName */,
                new KeySpecifier(KeyAlgorithms.NIST_P_256),
                endorsed_algs);
        key.setCertificatePath(cert_path.toArray(new X509Certificate[0]));
        key.setPrivateKey(privateKey);
        sess.closeSession();
        System.out.println("Imported Subject: " + cert_path.firstElement().getSubjectX500Principal().getName() + "\nID=#" + key.keyHandle +
                ", " + (rsaFlag ? "RSA" : "EC") + " Key with " + prot);
    }
}
