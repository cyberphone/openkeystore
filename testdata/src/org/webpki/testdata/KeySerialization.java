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
package org.webpki.testdata;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.XECKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.ArrayList;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.KeyAlgorithms;
//Std
import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONAsymKeyEncrypter;
import org.webpki.json.JSONX509Encrypter;
import org.webpki.json.JSONCryptoHelper;
import org.webpki.json.JSONDecryptionDecoder;
import org.webpki.json.JSONEncrypter;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;
import org.webpki.json.DataEncryptionAlgorithms;
import org.webpki.json.JSONSymKeyEncrypter;
import org.webpki.json.KeyEncryptionAlgorithms;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64;
import org.webpki.util.DebugFormatter;

/*
 * Test java (JCE) key serializations
 */
public class KeySerialization {
    static String baseKey;
    
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new Exception("Wrong number of arguments");
        }
        if (!System.clearProperty("bcprovider").isEmpty()) {
            CustomCryptoProvider.forcedLoad(true);
        }
        baseKey = args[0] + File.separator;
        test("p256", "secp256r", "EC");
        test("x25519", "x25519", "XDH");
    }
    
    static void swap(byte[] arr, int i, int j) {
        byte tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }

    static byte[] reverse(byte [] arr) {
        int i = 0;
        int j = arr.length - 1;

        while (i < j) {
            swap(arr, i, j);
            i++;
            j--;
        }
        return arr;
    }
    
    static byte[] readFile(String fileName) throws IOException {
        return ArrayUtil.readFile(baseKey + fileName);
    }
    
    static ArrayList<byte[]> readPEMObject(String fileName, String itemType) throws IOException {
        String pemString = new String(readFile(fileName), "utf-8");
        String header = "-----BEGIN " + itemType + "-----";
        String footer = "-----END "   + itemType + "-----";
        ArrayList<byte[]> objects = new ArrayList<>();
        int start = 0;
        while (true) {
            start = pemString.indexOf(header, start);
            if (start < 0) {
                if (objects.isEmpty()) {
                    throw new IOException("Didn't find any: " + header);
                }
                break;
            }
            int end = pemString.indexOf(footer, start);
            if (end < 0) throw new IOException("Expected to find: " + footer);
            objects.add(new Base64()
                .getBinaryFromBase64String(pemString.substring(start + header.length(), end)));
            start = end + footer.length();
        }
        return objects;
    }    

    static X509Certificate readPEMCertificate(String fileName) throws IOException, GeneralSecurityException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream
                (readPEMObject(fileName, "CERTIFICATE").get(0)));
    }

    static PublicKey readPEMPublicKey(String fileName, String keyFactory) throws IOException, GeneralSecurityException {
        KeyFactory kf = KeyFactory.getInstance(keyFactory);
        return kf.generatePublic(new X509EncodedKeySpec(readPEMObject(fileName, "PUBLIC KEY").get(0)));
    }
    
    static BigInteger getECCurvePoint(JSONObjectReader rd, 
                                      String property,
                                      KeyAlgorithms ec) throws IOException {
        byte[] fixedBinary = rd.getBinary(property);
        if (fixedBinary.length != (ec.getPublicKeySizeInBits() + 7) / 8) {
            throw new IOException("Public EC key parameter \"" + property + "\" is not normalized");
        }
        return new BigInteger(1, fixedBinary);
    }
    
    static void test(String filePrefix, String jceAlgorithm, String keyFactory) throws IOException, GeneralSecurityException {
        X509Certificate pemCert = readPEMCertificate(filePrefix + "certpath.pem");
        PublicKey publicKey = readPEMPublicKey(filePrefix + "publickey.pem", keyFactory);
        JSONObjectReader jwk = JSONParser.parse(readFile(filePrefix + "privatekey.jwk"));
        KeyAlgorithms keyAlgorithm = null;
        if (publicKey instanceof XECKey) {
            String algorithm = ((NamedParameterSpec)((XECKey)publicKey).getParams()).getName();
            keyAlgorithm = KeyAlgorithms.getKeyAlgorithmFromId(algorithm, AlgorithmPreferences.JOSE);
        } else {
            keyAlgorithm = KeyAlgorithms.getKeyAlgorithm(publicKey);
        }
        PublicKey reCreatedPublicKey = null;
        PublicKey reCreatedDynamicPublicKey = null;
        PublicKey generatedPublicKey = null;
        PublicKey jwkPublicKey = null;
        if (!pemCert.getPublicKey().equals(publicKey)) {
            throw new IOException("Cert + Public");
        }
        KeyFactory kf = KeyFactory.getInstance(keyFactory);
        if (keyAlgorithm.isEcdsa()) {
            reCreatedPublicKey = kf.generatePublic(
                    new ECPublicKeySpec(((ECPublicKey)publicKey).getW(), 
                                        keyAlgorithm.getECParameterSpec()));
            ECPoint w = new ECPoint(getECCurvePoint(jwk, JSONCryptoHelper.X_JSON, keyAlgorithm),
                                    getECCurvePoint(jwk, JSONCryptoHelper.Y_JSON, keyAlgorithm));
            jwkPublicKey = kf.generatePublic(
                    new ECPublicKeySpec(w, 
                                        keyAlgorithm.getECParameterSpec()));
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyFactory);
            kpg.initialize(new ECGenParameterSpec(keyAlgorithm.getJceName()), new SecureRandom());
            generatedPublicKey = kpg.generateKeyPair().getPublic();
            reCreatedDynamicPublicKey = kf.generatePublic(
                    new ECPublicKeySpec(((ECPublicKey)generatedPublicKey).getW(), 
                            keyAlgorithm.getECParameterSpec()));
        } else if (keyAlgorithm.isOkp()) {
            reCreatedPublicKey = kf.generatePublic(
                    new XECPublicKeySpec(((XECPublicKey)publicKey).getParams(), 
                                        ((XECPublicKey)publicKey).getU()));
            jwkPublicKey = kf.generatePublic(new XECPublicKeySpec(new NamedParameterSpec(keyAlgorithm.getJceName()),
                                             new BigInteger(reverse(jwk.getBinary(JSONCryptoHelper.X_JSON)))));
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyFactory);
            kpg.initialize(new NamedParameterSpec(keyAlgorithm.getJceName()));
            generatedPublicKey = kpg.generateKeyPair().getPublic();
            reCreatedDynamicPublicKey = kf.generatePublic(
                    new XECPublicKeySpec(new NamedParameterSpec(keyAlgorithm.getJceName()), 
                            ((XECPublicKey)generatedPublicKey).getU()));
        }
        if (reCreatedPublicKey == null) {
            return;
        }
        if (!reCreatedPublicKey.equals(publicKey)) {
            System.out.println("L1=" +
                              DebugFormatter.getHexDebugData(reCreatedPublicKey.getEncoded()) +
                              " L2=" +
                              DebugFormatter.getHexDebugData(publicKey.getEncoded()));
            throw new IOException("CrePublic + Public");
        }
        if (jwkPublicKey == null) {
            return;
        }
        if (!jwkPublicKey.equals(publicKey)) {
            System.out.println("L1=" +
                               DebugFormatter.getHexDebugData(jwkPublicKey.getEncoded()) +
                               "\nL2=" +
                               DebugFormatter.getHexDebugData(publicKey.getEncoded()));
            throw new IOException("JwkPublic + Public");
        }
        if (reCreatedDynamicPublicKey == null) {
            return;
        }
        if (!reCreatedDynamicPublicKey.equals(generatedPublicKey)) {
            throw new IOException("CreDynPublic + GenPublic");
        }
        System.out.println("Done: " + filePrefix);
    }
}
