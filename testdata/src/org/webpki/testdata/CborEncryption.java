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
import java.security.interfaces.RSAKey;

import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORSymKeyDecrypter;
import org.webpki.cbor.CBORSymKeyEncrypter;
import org.webpki.cbor.CBORAsymKeyDecrypter;
import org.webpki.cbor.CBORAsymKeyEncrypter;
import org.webpki.cbor.CBORDecrypter;
import org.webpki.cbor.CBOREncrypter;
import org.webpki.cbor.CBORIntegerMap;

import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.encryption.ContentEncryptionAlgorithms;
import org.webpki.crypto.encryption.KeyEncryptionAlgorithms;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;

// Test
import org.webpki.json.SymmetricKeys;

import org.webpki.util.ArrayUtil;
import org.webpki.util.PEMDecoder;

/*
 * Create JSF test vectors
 */
public class CborEncryption {
    static String baseKey;
    static String baseData;
    static String baseEncryption;
    static SymmetricKeys symmetricKeys;
    static String keyId;
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
            for (KeyEncryptionAlgorithms kea : KeyEncryptionAlgorithms.values()) {
                if (keyPairJwk.getPublic() instanceof RSAKey == kea.isRsa()) {
                    for (ContentEncryptionAlgorithms cea : ContentEncryptionAlgorithms.values()) {
                        asymKeyAllVariations(key, cea, kea);
                    }
                }
            }
        }
      
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
    }
 
    static void asymKeyAllVariations(String key,
                                     ContentEncryptionAlgorithms cea,
                                     KeyEncryptionAlgorithms kea) throws Exception {
        asymEncCore(key, false, false, cea, kea);
        asymEncCore(key, false, true,  cea, kea);
        asymEncCore(key, true,  false, cea, kea);
        asymEncCore(key, true,  true,  cea, kea);
    }

    static String prefix(String keyType) {
        return keyType + '#';
    }
    
    static String cleanEncryption(byte[] cefData) throws IOException {
        CBORIntegerMap decoded = CBORObject.decode(cefData).getIntegerMap();
        decoded.removeObject(CBOREncrypter.IV_LABEL.getInt());
        decoded.removeObject(CBOREncrypter.TAG_LABEL.getInt());
        decoded.removeObject(CBOREncrypter.CIPHER_TEXT_LABEL.getInt());
        if (decoded.hasKey(CBOREncrypter.KEY_ENCRYPTION_LABEL.getInt())) {
            CBORIntegerMap keyEncryption =
                    decoded.getObject(CBOREncrypter.KEY_ENCRYPTION_LABEL.getInt()).getIntegerMap();
            if (keyEncryption.hasKey(CBOREncrypter.CIPHER_TEXT_LABEL.getInt())) {
                keyEncryption.removeObject(CBOREncrypter.CIPHER_TEXT_LABEL.getInt());
            }
            if (keyEncryption.hasKey(CBOREncrypter.EPHEMERAL_KEY_LABEL.getInt())) {
                keyEncryption.removeObject(CBOREncrypter.EPHEMERAL_KEY_LABEL.getInt());
            }
        }
        return decoded.toString();
    }
    
    static void optionalUpdate(CBORDecrypter decrypter,
                               String fileName, 
                               byte[] updatedEncryption) throws IOException, GeneralSecurityException {
        boolean changed = true;
        byte[] oldEncryption = null;
        try {
            oldEncryption = ArrayUtil.readFile(fileName);
            try {
                compareResults(decrypter, oldEncryption);
            } catch (Exception e) {
                throw new GeneralSecurityException("ERROR - Old encryption '" + fileName + "' did not decrypt");
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

    static void compareResults(CBORDecrypter decrypter, byte[] encryptedData) throws Exception {
        if (!ArrayUtil.compare(decrypter.decrypt(encryptedData), dataToBeEncrypted)) {
            throw new GeneralSecurityException("Failed to decrypt");
        }
    }

    static void symKeyEncrypt(int keyBits, ContentEncryptionAlgorithms algorithm, boolean wantKeyId) throws Exception {
        byte[] key = symmetricKeys.getValue(keyBits);
        String keyName = symmetricKeys.getName(keyBits);
        CBORSymKeyEncrypter encrypter = new CBORSymKeyEncrypter(key, algorithm);
        if (wantKeyId) {
            encrypter.setKeyId(keyName);
        }
        byte[] encryptedData = encrypter.encrypt(dataToBeEncrypted).encode();
        CBORSymKeyDecrypter decrypter = new CBORSymKeyDecrypter(key);
        compareResults(decrypter, encryptedData);
        decrypter = new CBORSymKeyDecrypter(new CBORSymKeyDecrypter.KeyLocator() {

            @Override
            public byte[] locate(String arg0, ContentEncryptionAlgorithms arg1)
                    throws IOException, GeneralSecurityException {
                if (wantKeyId && !keyName.equals(arg0)) {
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
                       baseEncryption + prefix("a" + keyBits) + 
                       algorithm.getJoseAlgorithmId().toLowerCase() + '@' + 
                       keyIndicator(wantKeyId, false), encryptedData);
    }

    
    static KeyPair readJwk(String keyType) throws Exception {
        JSONObjectReader jwkPlus = JSONParser.parse(ArrayUtil.readFile(baseKey + keyType + "privatekey.jwk"));
        // Note: The built-in JWK decoder does not accept "kid" since it doesn't have a meaning in JSF or JEF. 
        if ((keyId = jwkPlus.getStringConditional("kid")) != null) {
            jwkPlus.removeProperty("kid");
        }
        return jwkPlus.getKeyPair();
    }
    
    
    static String keyIndicator(boolean wantKeyId, boolean wantPublicKey) {
        return (wantKeyId ? (wantPublicKey ? "pub+kid" : "kid") : wantPublicKey ? "pub" : "imp") + ".cbor";
    }
    
    static void asymEncCore(String keyType, 
                            boolean wantKeyId,
                            boolean wantPublicKey,
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
        byte[] encryptedData = encrypter.encrypt(dataToBeEncrypted).encode();
        CBORAsymKeyDecrypter decrypter = new CBORAsymKeyDecrypter(keyPair.getPrivate());
        compareResults(decrypter, encryptedData);
        decrypter = new CBORAsymKeyDecrypter(new CBORAsymKeyDecrypter.KeyLocator() {

            @Override
            public PrivateKey locate(PublicKey arg0, String arg1, KeyEncryptionAlgorithms arg2)
                    throws IOException, GeneralSecurityException {
                if (wantKeyId && !keyId.equals(arg1)) {
                    throw new GeneralSecurityException("missing key");
                }
                if (keyEncryptionAlgorithm != arg2) {
                    throw new GeneralSecurityException("alg mismatch");
                }
                return keyPair.getPrivate();
            }
            
        });
        compareResults(decrypter, encryptedData);
        optionalUpdate(decrypter, 
                       baseEncryption + keyType + "#" + keyEncryptionAlgorithm.getJoseAlgorithmId().toLowerCase() + 
                               "@" + contentEncryptionAlgorithm.getJoseAlgorithmId().toLowerCase() + '@' +
                       keyIndicator(wantKeyId, wantPublicKey), encryptedData);
    }
}