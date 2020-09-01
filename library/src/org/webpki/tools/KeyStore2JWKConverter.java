/*
 *  Copyright 2006-2020 WebPKI.org (http://webpki.org).
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
package org.webpki.tools;

import java.io.FileOutputStream;
import java.io.IOException;

import java.math.BigInteger;

import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.ArrayList;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.CryptoUtil;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.KeyStoreReader;
import org.webpki.crypto.CustomCryptoProvider;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;

public class KeyStore2JWKConverter {
    private static void fail() {
        System.out.println(KeyStore2JWKConverter.class.getName() + "  keystore-file password JWK-file qualifier\n" +
                "   qualifier = [public private certificate trust keyid javastring]");
        System.exit(3);
    }
    
    static LinkedHashMap<String,String> privateKeyInfo = new LinkedHashMap<>();
    
    static boolean privateKeyFlag;
    static boolean publicKeyFlag;
    static boolean certificateFlag;
    static boolean trustFlag;
    static boolean keyidFlag;
    static boolean javaFlag;
    static FileOutputStream fis;

    static void addPrivateKeyElement(String property, byte[] value) throws IOException {
        privateKeyInfo.put(property, Base64URL.encode(value));
    }

    static void setCryptoBinary(String name, BigInteger value) throws IOException {
        byte[] cryptoBinary = value.toByteArray();
        if (cryptoBinary[0] == 0x00) {
            byte[] woZero = new byte[cryptoBinary.length - 1];
            System.arraycopy(cryptoBinary, 1, woZero, 0, woZero.length);
            cryptoBinary = woZero;
        }
        addPrivateKeyElement(name, cryptoBinary);
    }
    
    public static void main(String argv[]) throws Exception {
        if (argv.length < 4) {
            fail();
        }
        for (int i = 3; i < argv.length; i++) {
            if (argv[i].equals("public")) {
                publicKeyFlag = true;
            } else if (argv[i].equals("private")) {
                privateKeyFlag = true;
            } else if (argv[i].equals("certificate")) {
                certificateFlag = true;
            } else if (argv[i].equals("trust")) {
                trustFlag = true;
            } else if (argv[i].equals("keyid")) {
                keyidFlag = true;
            } else if (argv[i].equals("javastring")) {
                javaFlag = true;
            } else {
                fail();
            }
        }
        CustomCryptoProvider.conditionalLoad(true);
        KeyStore ks = KeyStoreReader.loadKeyStore(argv[0], argv[1]);
        fis = new FileOutputStream(argv[2]);
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.isKeyEntry(alias)) {
                PublicKey publicKey = ks.getCertificateChain(alias)[0].getPublicKey();
                if (privateKeyFlag) {
                    KeyAlgorithms keyAlgorithm = KeyAlgorithms.getKeyAlgorithm(publicKey);
                    PrivateKey privateKey = (PrivateKey)ks.getKey(alias, argv[1].toCharArray());
                    if (keyAlgorithm.isRsa()) {
                        RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey)privateKey;
                        setCryptoBinary("d", rsaPrivateKey.getPrivateExponent());
                        setCryptoBinary("p", rsaPrivateKey.getPrimeP());
                        setCryptoBinary("q", rsaPrivateKey.getPrimeQ());
                        setCryptoBinary("dp", rsaPrivateKey.getPrimeExponentP());
                        setCryptoBinary("dq", rsaPrivateKey.getPrimeExponentQ());
                        setCryptoBinary("qi", rsaPrivateKey.getCrtCoefficient());
                    } else if (keyAlgorithm.isEcdsa()) {
                       BigInteger d = ((ECPrivateKey)privateKey).getS();
                       byte[] curvePoint = d.toByteArray();
                       if (curvePoint.length > (keyAlgorithm.getPublicKeySizeInBits() + 7) / 8) {
                           if (curvePoint[0] != 0) {
                               throw new IOException("Unexpected EC value");
                           }
                           setCryptoBinary("d", d);
                       } else {
                           while (curvePoint.length < (keyAlgorithm.getPublicKeySizeInBits() + 7) / 8) {
                               curvePoint = ArrayUtil.add(new byte[]{0}, curvePoint);
                           }
                           addPrivateKeyElement("d", curvePoint);
                       }
                    } else {
                        addPrivateKeyElement("d", CryptoUtil.private2RawOkpKey(privateKey, keyAlgorithm));
                    }
                    writeJwk(fis, publicKey, alias);
                }
                if (certificateFlag) {
                    ArrayList<X509Certificate> certPath = new ArrayList<>();
                    for (Certificate cert : ks.getCertificateChain(alias)) {
                        certPath.add((X509Certificate) cert);
                    }
                    writeCert(fis, certPath.toArray(new X509Certificate[0]));
                }
                if (publicKeyFlag) {
                    writeJwk(fis, publicKey, alias);
                }
            } else if (ks.isCertificateEntry(alias)) {
                if (trustFlag) {
                    writeCert(fis, new X509Certificate[]{(X509Certificate) ks.getCertificate(alias)});
                }
            } else {
                throw new Exception("Bad KS");
            }
        }
    }

    static void writeJwk(FileOutputStream fis, 
                         PublicKey publicKey,
                         String keyId) throws Exception {
        JSONObjectWriter jwk = JSONObjectWriter.createCorePublicKey(publicKey, AlgorithmPreferences.JOSE_ACCEPT_PREFER);
        for (String key : privateKeyInfo.keySet()) {
            jwk.setString(key, privateKeyInfo.get(key));
        }
        String key = jwk.serializeToString(JSONOutputFormats.NORMALIZED);
        if (keyidFlag) {
            key = "{\"kid\":\"" + keyId + "\"," + key.substring(1);
        }
        printIt(JSONParser.parse(key).toString());

    }

    static void writeCert(FileOutputStream fis, X509Certificate[] certificatePath) throws Exception {
        printIt(JSONArrayWriter.createCoreCertificatePath(certificatePath).serializeToString(JSONOutputFormats.PRETTY_PRINT));
    }

    static void printIt(String key) throws IOException {
        if (javaFlag) {
            key = key.replace("\"", "\\\"");
            StringBuilder s = new StringBuilder("\"");
            int count = 1;
            for (char c : key.trim().toCharArray()) {
                if (c == '\n') {
                    s.append("\" +\n\"");
                    count = 0;
                    continue;
                }
                if (count == 100) {
                    s.append("\" +\n\"");
                    count = 0;
                }
                count++;
                s.append(c);
            }
            key = s.append('\"').toString();
        }
        fis.write(key.getBytes("utf-8"));
    }
}
