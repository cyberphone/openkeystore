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
package org.webpki.testdata;

import java.io.File;
import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import java.security.interfaces.RSAKey;

import java.util.ArrayList;

import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORSymKeyDecrypter;
import org.webpki.cbor.CBORSymKeyEncrypter;
import org.webpki.cbor.CBORTag;
import org.webpki.cbor.CBORTest;
import org.webpki.cbor.CBORTextString;
import org.webpki.cbor.CBORX509Decrypter;
import org.webpki.cbor.CBORX509Encrypter;
import org.webpki.cbor.CBORArray;
import org.webpki.cbor.CBORAsymKeyDecrypter;
import org.webpki.cbor.CBORAsymKeyEncrypter;
import org.webpki.cbor.CBORDecrypter;
import org.webpki.cbor.CBORCryptoConstants;
import org.webpki.cbor.CBORCryptoUtils;
import org.webpki.cbor.CBORMap;

import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.KeyEncryptionAlgorithms;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;

// Test
import org.webpki.json.SymmetricKeys;

import org.webpki.util.ArrayUtil;
import org.webpki.util.HexaDecimal;
import org.webpki.util.PEMDecoder;

/*
 * Create JSF test vectors
 */
public class CborEncryption {
    static String baseKey;
    static String baseData;
    static String baseEncryption;
    static SymmetricKeys symmetricKeys;
    static CBORObject keyId;
    static byte[] dataToBeEncrypted;
   

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            throw new Exception("Wrong number of arguments");
        }
        CustomCryptoProvider.forcedLoad(false);
        baseKey = args[0] + File.separator;
        baseData = args[1] + File.separator;
        baseEncryption = args[2] + File.separator;
        symmetricKeys = new SymmetricKeys(baseKey);
        dataToBeEncrypted = ArrayUtil.readFile(baseData + "datatobeencrypted.txt");

        for (String key : new String[]{"p256", "p384", "p521", "r2048", "x25519", "x448"}) {
            // Check the PEM reader
            KeyPair keyPairPem = 
                    new KeyPair(PEMDecoder.getPublicKey(ArrayUtil.readFile(baseKey + key + "publickey.pem")),
                                PEMDecoder.getPrivateKey(ArrayUtil.readFile(baseKey + key + "privatekey.pem")));
            KeyPair keyPairJwk = readJwk(key);
            if (!keyPairJwk.getPublic().equals(keyPairPem.getPublic())) {
                throw new IOException("PEM fail at public " + key);
            }
            if (!keyPairJwk.getPrivate().equals(keyPairPem.getPrivate())) {
                throw new IOException("PEM fail at private " + key);
            }
            KeyStore keyStorePem = 
                    PEMDecoder.getKeyStore(ArrayUtil.readFile(baseKey + key + "certificate-key.pem"),
                                                              "mykey", "foo123");
            if (!keyPairJwk.getPrivate().equals(keyStorePem.getKey("mykey",
                                                                   "foo123".toCharArray()))) {
                throw new IOException("PEM KS fail at private " + key);
            }
            if (!keyPairJwk.getPublic().equals(keyStorePem.getCertificate("mykey").getPublicKey())) {
                throw new IOException("PEM KS fail at public " + key);
            }
            ArrayList<X509Certificate> certPath = new ArrayList<>();
            for (Certificate certificate : keyStorePem.getCertificateChain("mykey")) {
                certPath.add((X509Certificate) certificate);
            }
            for (KeyEncryptionAlgorithms kea : KeyEncryptionAlgorithms.values()) {
                if (keyPairJwk.getPublic() instanceof RSAKey == kea.isRsa()) {
                    for (ContentEncryptionAlgorithms cea : ContentEncryptionAlgorithms.values()) {
                        asymKeyAllVariations(key, cea, kea);
                        certEncryption(key, certPath.toArray(new X509Certificate[0]), cea, kea);
                    }
                }
            }
        }
        
        asymEncCore("p256", false, true, 1, false, 
                    ContentEncryptionAlgorithms.A256GCM, KeyEncryptionAlgorithms.ECDH_ES_A256KW);
        asymEncCore("p256", false, true, 2, false, 
                ContentEncryptionAlgorithms.A256GCM, KeyEncryptionAlgorithms.ECDH_ES_A256KW);
        asymEncCore("x25519", false, true, 0, true, 
                    ContentEncryptionAlgorithms.A256GCM, KeyEncryptionAlgorithms.ECDH_ES);
        asymEncCore("x25519", false, true, 1, true, 
                ContentEncryptionAlgorithms.A256GCM, KeyEncryptionAlgorithms.ECDH_ES);
             
        for (int i = 0; i < 2; i++) {
            for (ContentEncryptionAlgorithms alg : ContentEncryptionAlgorithms.values()) {
                for (int keySize : new int[] {128, 256, 384, 512})
                try {
                    symKeyEncrypt(keySize, alg, i == 0);
                    if (symmetricKeys.getValue(keySize).length != alg.getKeyLength()) {
                        throw new GeneralSecurityException("Should have thrown");
                    }
                } catch (Exception e) {
                    if (symmetricKeys.getValue(keySize).length == alg.getKeyLength()) {
                        throw new GeneralSecurityException("Shouldn't have thrown");
                    }
                }
            }
        }
        
        demoDocEncryption("demo-doc-encryption");
    }
 
    static void certEncryption(String keyType, 
                               X509Certificate[] certificatePath,
                               ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                               KeyEncryptionAlgorithms keyEncryptionAlgorithm) throws Exception {
        KeyPair keyPair = readJwk(keyType);
        CBORX509Encrypter encrypter = 
                new CBORX509Encrypter(certificatePath, keyEncryptionAlgorithm, contentEncryptionAlgorithm);
        byte[] encryptedData = encrypter.encrypt(dataToBeEncrypted).encode();
        CBORX509Decrypter decrypter = new CBORX509Decrypter(new CBORX509Decrypter.KeyLocator() {

            @Override
            public PrivateKey locate(X509Certificate[] cp,
                                     KeyEncryptionAlgorithms kea,
                                     ContentEncryptionAlgorithms cea)
                    throws IOException, GeneralSecurityException {
                if (certificatePath.length != cp.length) {
                    throw new GeneralSecurityException("cer mismatch");
                }
                for (int i = 0; i < cp.length ; i++) {
                    if (!certificatePath[i].equals(cp[i])) {
                        throw new GeneralSecurityException("cer2 mismatch");
                    }
                }
                if (keyEncryptionAlgorithm != kea) {
                    throw new GeneralSecurityException("kea mismatch");
                }
                if (contentEncryptionAlgorithm != cea) {
                    throw new GeneralSecurityException("cea mismatch");
                }
                return keyPair.getPrivate();
            }
            
        });
        compareResults(decrypter, encryptedData);
        optionalUpdate(decrypter, 
                       baseEncryption + keyType + "#" + keyEncryptionAlgorithm.getJoseAlgorithmId().toLowerCase() + 
                               "@" + contentEncryptionAlgorithm.getJoseAlgorithmId().toLowerCase() + '@' +
                       "cer.cbor", encryptedData);
    }

    static void asymKeyAllVariations(String key,
                                     ContentEncryptionAlgorithms cea,
                                     KeyEncryptionAlgorithms kea) throws Exception {
        asymEncCore(key, false, false, 0, false, cea, kea);
        asymEncCore(key, false, true,  0, false, cea, kea);
        asymEncCore(key, true,  false, 0, false, cea, kea);
    }

    static String cleanEncryption(byte[] cefData) throws IOException {
        CBORObject cborObject = CBORObject.decode(cefData);
        CBORMap decoded = CBORCryptoUtils.unwrapContainerMap(cborObject,
                                                             CBORCryptoUtils.POLICY.OPTIONAL);
        decoded.removeObject(CBORCryptoConstants.IV_LABEL);
        decoded.removeObject(CBORCryptoConstants.TAG_LABEL);
        decoded.removeObject(CBORCryptoConstants.CIPHER_TEXT_LABEL);
        if (decoded.hasKey(CBORCryptoConstants.KEY_ENCRYPTION_LABEL)) {
            CBORMap keyEncryption =
                    decoded.getObject(CBORCryptoConstants.KEY_ENCRYPTION_LABEL).getMap();
            if (keyEncryption.hasKey(CBORCryptoConstants.CIPHER_TEXT_LABEL)) {
                keyEncryption.removeObject(CBORCryptoConstants.CIPHER_TEXT_LABEL);
            }
            if (keyEncryption.hasKey(CBORCryptoConstants.EPHEMERAL_KEY_LABEL)) {
                keyEncryption.removeObject(CBORCryptoConstants.EPHEMERAL_KEY_LABEL);
            }
        }
        return cborObject.toString();
    }
    
    static void optionalUpdate(CBORDecrypter decrypter,
                               String fileName, 
                               byte[] updatedEncryption) throws IOException, 
                                                                GeneralSecurityException {
        boolean changed = true;
        byte[] oldEncryption = null;
        try {
            oldEncryption = ArrayUtil.readFile(fileName);
            try {
                compareResults(decrypter, oldEncryption);
            } catch (Exception e) {
                throw new GeneralSecurityException("ERROR - Old encryption '" + 
                                                   fileName + "' did not decrypt");
            }
        } catch (IOException e) {
            changed = false;  // New file
        }
        if (oldEncryption != null &&
            cleanEncryption(oldEncryption).equals(cleanEncryption(updatedEncryption))) {
            return;
        }
        ArrayUtil.writeFile(fileName, updatedEncryption);
        if (changed) {
            System.out.println("WARNING '" + fileName + "' was UPDATED");
        }
        return;
    }

    static void compareResults(CBORDecrypter decrypter, 
                               byte[] encryptedData) throws Exception {
        if (!ArrayUtil.compare(decrypter.decrypt(CBORObject.decode(encryptedData)), 
                               dataToBeEncrypted)) {
            throw new GeneralSecurityException("Failed to decrypt");
        }
    }

    static void symKeyEncrypt(int keyBits, 
                              ContentEncryptionAlgorithms algorithm, 
                              boolean wantKeyId) throws Exception {
        byte[] key = symmetricKeys.getValue(keyBits);
        CBORObject keyName = new CBORTextString(symmetricKeys.getName(keyBits));
        CBORSymKeyEncrypter encrypter = new CBORSymKeyEncrypter(key, algorithm);
        if (wantKeyId) {
            encrypter.setKeyId(keyName);
        }
        byte[] encryptedData = encrypter.encrypt(dataToBeEncrypted).encode();
        CBORSymKeyDecrypter decrypter = new CBORSymKeyDecrypter(key);
        compareResults(decrypter, encryptedData);
        decrypter = new CBORSymKeyDecrypter(new CBORSymKeyDecrypter.KeyLocator() {

            @Override
            public byte[] locate(CBORObject optionalKeyId, ContentEncryptionAlgorithms arg1)
                    throws IOException, GeneralSecurityException {
//TODO
                if (wantKeyId && !CBORTest.compareKeyId(keyName, optionalKeyId)) {
                    throw new GeneralSecurityException("missing key");
                }
                if (algorithm != arg1) {
                    throw new GeneralSecurityException("alg mismatch");
                }
                return key;
            }
            
        });
        compareResults(decrypter, encryptedData);
        optionalUpdate(decrypter, 
                       baseEncryption + "a" + keyBits + "#" + 
                       algorithm.getJoseAlgorithmId().toLowerCase() + '@' + 
                       keyIndicator(wantKeyId, false, 0, false), encryptedData);
    }

    
    static KeyPair readJwk(String keyType) throws Exception {
        JSONObjectReader jwkPlus = JSONParser.parse(ArrayUtil.readFile(baseKey + keyType + "privatekey.jwk"));
        // Note: The built-in JWK decoder does not accept "kid" since it doesn't have a meaning in JSF or JEF. 
        keyId = new CBORTextString(jwkPlus.getString("kid"));
        jwkPlus.removeProperty("kid");
        return jwkPlus.getKeyPair();
    }
    
    
    static String keyIndicator(boolean wantKeyId, 
                               boolean wantPublicKey,
                               int tagged,
                               boolean customData) {
        return  (tagged == 1 ? "tag1dim." : tagged == 2 ? "tag2dim." : "") + (customData ? "custdat." : "") +
                (wantKeyId ? "kid" : wantPublicKey ? "pub" : "imp") + ".cbor";
    }
    
    static void asymEncCore(String keyType, 
                            boolean wantKeyId,
                            boolean wantPublicKey,
                            int tagged,
                            boolean customData,
                            ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                            KeyEncryptionAlgorithms keyEncryptionAlgorithm) throws Exception {
        KeyPair keyPair = readJwk(keyType);
        CBORAsymKeyEncrypter encrypter = 
                new CBORAsymKeyEncrypter(keyPair.getPublic(), keyEncryptionAlgorithm, contentEncryptionAlgorithm);
        if (wantKeyId) {
            encrypter.setKeyId(keyId);
        }
        if (wantPublicKey) {
            encrypter.setPublicKeyOption(true);
        }
        if (tagged != 0) {
            encrypter.setIntercepter(new CBORCryptoUtils.Intercepter() {
                
                @Override
                public CBORObject wrap(CBORMap encryptionObject) 
                        throws IOException, GeneralSecurityException {
                    
                    // 1-dimensional or 2-dimensional tag
                    return new CBORTag(211, tagged == 1 ? 
                            encryptionObject : new CBORArray()
                                .addObject(new CBORTextString("https://example.com/myobject"))
                                .addObject(encryptionObject));
                    
                }
                
                @Override
                public CBORObject getCustomData() throws IOException, GeneralSecurityException {
                    return customData ? new CBORTextString("Any valid CBOR object") : null;
                }

            });
        } else if (customData) {
            encrypter.setIntercepter(new CBORCryptoUtils.Intercepter() {
                
                @Override
                public CBORObject getCustomData() throws IOException, GeneralSecurityException {
                    return new CBORTextString("Any valid CBOR object");
                }

            });
        }
        byte[] encryptedData = encrypter.encrypt(dataToBeEncrypted).encode();
        CBORAsymKeyDecrypter decrypter = 
                new CBORAsymKeyDecrypter(new CBORAsymKeyDecrypter.KeyLocator() {

            @Override
            public PrivateKey locate(PublicKey optionalPublicKey,
                                     CBORObject optionalKeyId, 
                                     KeyEncryptionAlgorithms kea,
                                     ContentEncryptionAlgorithms cea)
                    throws IOException, GeneralSecurityException {
                if (wantKeyId && !CBORTest.compareKeyId(keyId, optionalKeyId)) {
                    throw new GeneralSecurityException("missing key");
                }
                if (keyEncryptionAlgorithm != kea) {
                    throw new GeneralSecurityException("kea mismatch");
                }
                if (contentEncryptionAlgorithm != cea) {
                    throw new GeneralSecurityException("cea mismatch");
                }
                return keyPair.getPrivate();
            }
            
        });
        if (customData) {
            decrypter.setCustomDataPolicy(CBORCryptoUtils.POLICY.MANDATORY);
        }
        if (tagged != 0) {
            decrypter.setTagPolicy(CBORCryptoUtils.POLICY.MANDATORY);
        }
        compareResults(decrypter, encryptedData);
        optionalUpdate(decrypter, 
                       baseEncryption + keyType + "#" + keyEncryptionAlgorithm.getJoseAlgorithmId().toLowerCase() + 
                               "@" + contentEncryptionAlgorithm.getJoseAlgorithmId().toLowerCase() + '@' +
                       keyIndicator(wantKeyId, wantPublicKey, tagged, customData), encryptedData);
    }
    
    static void demoDocEncryption(String fileName) throws IOException {
        fileName = baseEncryption + fileName;
        byte[] encryption = ArrayUtil.readFile(baseEncryption + "x25519#ecdh-es+a256kw@a256gcm@kid.cbor"); 
        ArrayUtil.writeFile(fileName + ".hex", 
                            HexaDecimal.encode(encryption).getBytes("utf-8"));
        StringBuilder text = new StringBuilder(CBORObject.decode(encryption).toString());
        int i = text.indexOf("\n  1:");
        for (String comment : new String[]{"Content encryption algorithm = A256GCM",
                                           "Key encryption object",
                                           "Key encryption algorithm = ECDH-ES+A256KW",
                                           "Key Id",
                                           "Ephemeral public key descriptor in COSE format",
                                           "kty = OKP",
                                           "crv = X25519",
                                           "x",
                                           "CipherText (Encrypted key)",
                                           "Tag",
                                           "Initialization Vector (IV)",
                                           "Ciphertext (Encrypted Content)"}) {
            while (true) {
                int spaces = 0;
                while (text.charAt(++i) == ' ') {
                    spaces++;
                };
                if (text.charAt(i) == '}') {
                    i = text.indexOf("\n", i);
                    continue;
                }
                text.insert(i - spaces, "<div style='height:0.5em'></div>");
                i += 32;
                for (int q = 0; q < spaces; q++) {
                    text.insert(i - spaces, ' ');
                }
                String added = "<span style='color:grey'>/ " + comment + " /</span>\n";
                text.insert(i, added);
                i = text.indexOf("\n", i + added.length() + spaces);
                break;
            }
        }
        ArrayUtil.writeFile(fileName + ".txt", 
                            text.toString()
                                .replace("\n", "<br>\n")
                                .replace("  ", "&nbsp;&nbsp;").getBytes("utf-8"));
    }

}