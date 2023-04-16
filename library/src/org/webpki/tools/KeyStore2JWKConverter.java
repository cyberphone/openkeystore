/*
 *  Copyright 2006-2021 WebPKI.org (http://webpki.org).
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
import org.webpki.crypto.OkpSupport;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.KeyStoreReader;
import org.webpki.crypto.CustomCryptoProvider;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.util.IO;
import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;

public class KeyStore2JWKConverter {

    public KeyStore2JWKConverter() {
        
    }

    LinkedHashMap<String,String> privateKeyInfo;
    
    String keyId;
    
    StringBuilder keyData = new StringBuilder();
    
    private void addKeyObject(String keyObjrect) {
        if (keyData.length() != 0) {
            keyData.append('\n');
        }
        keyData.append(keyObjrect);
    }

    private static void fail() {
        System.out.println(KeyStore2JWKConverter.class.getName() + "  keystore-file password JWK-file qualifier\n" +
                "   qualifier = [public private certpath trust keyid javastring]");
        System.exit(3);
    }

    void addPrivateKeyElement(String property, byte[] value) throws IOException {
        privateKeyInfo.put(property, Base64URL.encode(value));
    }

    void setCryptoBinary(String name, BigInteger value) throws IOException {
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
        boolean privateKeyFlag = false;
        boolean publicKeyFlag = false;
        boolean certificatePathFlag = false;
        boolean trustFlag = false;
        boolean keyIdFlag = false;
        boolean javaFlag = false;
        for (int i = 3; i < argv.length; i++) {
            if (argv[i].equals("public")) {
                publicKeyFlag = true;
            } else if (argv[i].equals("private")) {
                privateKeyFlag = true;
            } else if (argv[i].equals("certpath")) {
                certificatePathFlag = true;
            } else if (argv[i].equals("trust")) {
                trustFlag = true;
            } else if (argv[i].equals("keyid")) {
                keyIdFlag = true;
            } else if (argv[i].equals("javastring")) {
                javaFlag = true;
            } else {
                fail();
            }
        }
        CustomCryptoProvider.conditionalLoad(true);
        KeyStore ks = KeyStoreReader.loadKeyStore(argv[0], argv[1]);
        KeyStore2JWKConverter converter = new KeyStore2JWKConverter();
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.isKeyEntry(alias)) {
                if (keyIdFlag && (publicKeyFlag || privateKeyFlag)) {
                    converter.setKeyId(alias);
                }
                PublicKey publicKey = ks.getCertificateChain(alias)[0].getPublicKey();
                if (privateKeyFlag) {
                    converter.addKeyObject(converter.writePrivateKey(
                            (PrivateKey)ks.getKey(alias, argv[1].toCharArray()),
                            publicKey));
                }
                if (certificatePathFlag) {
                    ArrayList<X509Certificate> certPath = new ArrayList<>();
                    for (Certificate cert : ks.getCertificateChain(alias)) {
                        certPath.add((X509Certificate) cert);
                    }
                    converter.writeCert(certPath.toArray(new X509Certificate[0]));
                }
                if (publicKeyFlag) {
                    converter.addKeyObject(converter.writePublicKey(publicKey));
                }
            } else if (ks.isCertificateEntry(alias)) {
                if (trustFlag) {
                    converter.writeCert(new X509Certificate[]{(X509Certificate) ks.getCertificate(alias)});
                }
            } else {
                throw new Exception("Bad KS");
            }
            converter.setKeyId(null);
        }
        String total = converter.keyData.toString();
        if (javaFlag) {
            if (javaFlag) {
                total = total.replace("\"", "\\\"");
                StringBuilder s = new StringBuilder("\"");
                int count = 1;
                for (char c : total.trim().toCharArray()) {
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
                total = s.append('\"').toString();
            }            
        }
        IO.writeFile(argv[2], total.getBytes("utf-8"));
    }

    private void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String writePrivateKey(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        JSONObjectWriter jwk = new JSONObjectWriter(JSONParser.parse(writePublicKey(publicKey)));
        privateKeyInfo = new LinkedHashMap<>();
        KeyAlgorithms keyAlgorithm = KeyAlgorithms.getKeyAlgorithm(publicKey);
        switch (keyAlgorithm.getKeyType()) {
        case RSA:
            RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey)privateKey;
            setCryptoBinary("d", rsaPrivateKey.getPrivateExponent());
            setCryptoBinary("p", rsaPrivateKey.getPrimeP());
            setCryptoBinary("q", rsaPrivateKey.getPrimeQ());
            setCryptoBinary("dp", rsaPrivateKey.getPrimeExponentP());
            setCryptoBinary("dq", rsaPrivateKey.getPrimeExponentQ());
            setCryptoBinary("qi", rsaPrivateKey.getCrtCoefficient());
            break;
        case EC:
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
           break;
        default:
            addPrivateKeyElement("d", OkpSupport.private2RawKey(privateKey, keyAlgorithm));
        }
        for (String key : privateKeyInfo.keySet()) {
            jwk.setString(key, privateKeyInfo.get(key));
        }
        return jwk.toString();
    }

    public String writePublicKey(PublicKey publicKey) throws Exception {
        String jwk = JSONObjectWriter.createCorePublicKey(
                publicKey, AlgorithmPreferences.JOSE_ACCEPT_PREFER)
                    .serializeToString(JSONOutputFormats.NORMALIZED);
        if (keyId != null) {
            jwk = "{\"kid\":\"" + keyId + "\"," + jwk.substring(1);
        }
        return JSONParser.parse(jwk).toString();
    }

    void writeCert(X509Certificate[] certificatePath) throws Exception {
        addKeyObject(JSONArrayWriter.createCoreCertificatePath(certificatePath).toString());
    }
}
