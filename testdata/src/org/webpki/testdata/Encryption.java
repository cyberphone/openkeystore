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

import java.security.cert.X509Certificate;

import java.security.interfaces.RSAKey;

import java.util.ArrayList;

import org.webpki.crypto.CustomCryptoProvider;

//Std
import org.webpki.crypto.encryption.ContentEncryptionAlgorithms;
import org.webpki.crypto.encryption.KeyEncryptionAlgorithms;

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
import org.webpki.json.JSONSymKeyEncrypter;
// Test
import org.webpki.json.SymmetricKeys;
import org.webpki.json.Extension1;
import org.webpki.json.Extension2;

import org.webpki.util.ArrayUtil;
import org.webpki.util.PEMDecoder;

/*
 * Create JEF test vectors
 */
public class Encryption {
    static String baseKey;
    static String baseEncryption;
    static String baseData;
    static SymmetricKeys symmetricKeys;
    static String keyId;
    static byte[] dataToBeEncrypted;
    
    public interface LocalDecrypt {
        public byte[] decrypt(JSONObjectReader reader) throws Exception;
    }

    static void cleanInner(JSONObjectReader inner) throws Exception {
        if (inner.hasProperty(JSONCryptoHelper.ENCRYPTED_KEY_JSON)) {
            inner.removeProperty(JSONCryptoHelper.ENCRYPTED_KEY_JSON);
        }
        if (inner.hasProperty(JSONCryptoHelper.EPHEMERAL_KEY_JSON)) {
            inner.removeProperty(JSONCryptoHelper.EPHEMERAL_KEY_JSON);
        }
     }

    static String cleanEncryption(JSONObjectReader encryptedData) throws Exception {
        encryptedData.removeProperty(JSONCryptoHelper.IV_JSON);
        encryptedData.removeProperty(JSONCryptoHelper.TAG_JSON);
        encryptedData.removeProperty(JSONCryptoHelper.CIPHER_TEXT_JSON);
        if (encryptedData.hasProperty(JSONCryptoHelper.RECIPIENTS_JSON)) {
            JSONArrayReader recipients = encryptedData.getArray(JSONCryptoHelper.RECIPIENTS_JSON);
            do {
                cleanInner(recipients.getObject());
            } while (recipients.hasMore());
        } else if (encryptedData.hasProperty(JSONCryptoHelper.KEY_ENCRYPTION_JSON)) {
            cleanInner(encryptedData.getObject(JSONCryptoHelper.KEY_ENCRYPTION_JSON));
        } else {
            cleanInner(encryptedData);
        }
        return encryptedData.toString();
    }

    static void optionalUpdate(String baseName, byte[] encryptedData, LocalDecrypt decrypter) throws Exception {
        String fileName = baseEncryption + baseName;
        JSONObjectReader newEncryptedData = JSONParser.parse(encryptedData);
        if (!ArrayUtil.compare(decrypter.decrypt(newEncryptedData), dataToBeEncrypted)) {
            throw new IOException("Decrypt err:" + baseName);
        }
        boolean changed = true;
        try {
            JSONObjectReader oldEncryptedData = JSONParser.parse(ArrayUtil.readFile(fileName));
            try {
                if (ArrayUtil.compare(decrypter.decrypt(oldEncryptedData), dataToBeEncrypted)) {
                    // All good but are the new and old effectively the same?
                    if (cleanEncryption(newEncryptedData).equals(cleanEncryption(oldEncryptedData))) {
                        return;  // Yes, don't rewrite.
                    }
                }
            } catch (Exception e) {}
        } catch (Exception  e) {
            changed = false;  // New I guess
        }
        if (changed) {
            System.out.println("UPDATED: " + baseName);
        }
        ArrayUtil.writeFile(fileName, encryptedData);
    }

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
        
        asymEnc("p256", ContentEncryptionAlgorithms.A128CBC_HS256_ALG_ID);
        asymEnc("p256", ContentEncryptionAlgorithms.A256CBC_HS512_ALG_ID);
        asymEnc("p384", ContentEncryptionAlgorithms.A256CBC_HS512_ALG_ID);
        asymEnc("p384", ContentEncryptionAlgorithms.A128CBC_HS256_ALG_ID);
        asymEnc("p521", ContentEncryptionAlgorithms.A128GCM_ALG_ID);
        asymEnc("p521", ContentEncryptionAlgorithms.A128CBC_HS256_ALG_ID);
        asymEnc("r2048", ContentEncryptionAlgorithms.A256GCM_ALG_ID);
        asymEnc("x25519", ContentEncryptionAlgorithms.A256GCM_ALG_ID);
        asymEnc("x448", ContentEncryptionAlgorithms.A256CBC_HS512_ALG_ID);

        asymEncNoPublicKeyInfo("p256", ContentEncryptionAlgorithms.A128CBC_HS256_ALG_ID, true);
        asymEncNoPublicKeyInfo("p256", ContentEncryptionAlgorithms.A128GCM_ALG_ID, true);
        asymEncNoPublicKeyInfo("r2048", ContentEncryptionAlgorithms.A256GCM_ALG_ID, true);
        asymEncNoPublicKeyInfo("r2048", ContentEncryptionAlgorithms.A128GCM_ALG_ID, true);
        asymEncNoPublicKeyInfo("p256", ContentEncryptionAlgorithms.A128GCM_ALG_ID, false);
        asymEncNoPublicKeyInfo("r2048", ContentEncryptionAlgorithms.A256GCM_ALG_ID, false);
        asymEncNoPublicKeyInfo("x25519", ContentEncryptionAlgorithms.A128GCM_ALG_ID, false);
        asymEncNoPublicKeyInfo("x448", ContentEncryptionAlgorithms.A256GCM_ALG_ID, true);
        
        certEnc("p256", ContentEncryptionAlgorithms.A128CBC_HS256_ALG_ID);
        certEnc("r2048", ContentEncryptionAlgorithms.A256GCM_ALG_ID);
        certEnc("x25519", ContentEncryptionAlgorithms.A256GCM_ALG_ID);
        
        multipleAsymEnc(new String[]{"p256", "p384"}, 
                         ContentEncryptionAlgorithms.A128CBC_HS256_ALG_ID, 
                        true);
      
        multipleAsymEnc(new String[]{"p256", "p384"}, 
                        ContentEncryptionAlgorithms.A128CBC_HS256_ALG_ID, 
                        false);

        multipleAsymEnc(new String[]{"p256", "p384"}, 
                        ContentEncryptionAlgorithms.A256CBC_HS512_ALG_ID, 
                        false);

        multipleAsymEnc(new String[]{"p256", "r2048"}, 
                        ContentEncryptionAlgorithms.A128CBC_HS256_ALG_ID, 
                        true);

        multipleAsymEnc(new String[]{"p256", "p256-2"}, 
                        ContentEncryptionAlgorithms.A128CBC_HS256_ALG_ID, 
                        true);

        multipleAsymEnc(new String[]{"p521", "x448"}, 
                        ContentEncryptionAlgorithms.A256CBC_HS512_ALG_ID, 
                        false);

        symmEnc(256, ContentEncryptionAlgorithms.A128CBC_HS256_ALG_ID);
        symmEnc(512, ContentEncryptionAlgorithms.A256CBC_HS512_ALG_ID);
        symmEnc(128, ContentEncryptionAlgorithms.A128GCM_ALG_ID);
        symmEnc(256, ContentEncryptionAlgorithms.A256GCM_ALG_ID);

        coreSymmEnc(256, "imp.json", ContentEncryptionAlgorithms.A256GCM_ALG_ID, false);
        
        coreAsymEnc("p256", 
                    "exts-jwk.json",
                    ContentEncryptionAlgorithms.A256GCM_ALG_ID,
                    false,
                    true,
                    new JSONCryptoHelper.ExtensionHolder()
                        .addExtension(Extension1.class, true)
                        .addExtension(Extension2.class, true),
                    new JSONObjectWriter()
                        .setString(new Extension1().getExtensionUri(), "something")
                        .setObject(new Extension2().getExtensionUri(), 
                            new JSONObjectWriter().setBoolean("life-is-great", true)));

        coreAsymEnc("p256", 
                    "jwk+kid.json",
                    ContentEncryptionAlgorithms.A256GCM_ALG_ID,
                    true,
                    true,
                    null,
                    null);
    }

    static X509Certificate[] getCertificatePath(String keyType)
            throws IOException, GeneralSecurityException {
        return PEMDecoder.getCertificatePath(ArrayUtil.readFile(baseKey + keyType + "certpath.pem"));
    }

    static void certEnc(String keyType, 
                        ContentEncryptionAlgorithms contentEncryptionAlgorithm) throws Exception {
        KeyPair keyPair = readJwk(keyType);
        KeyEncryptionAlgorithms keyEncryptionAlgorithm = KeyEncryptionAlgorithms.RSA_OAEP_256_ALG_ID;
        if (!(keyPair.getPublic() instanceof RSAKey)) {
            switch (contentEncryptionAlgorithm.getKeyLength()) {
            case 16: 
                keyEncryptionAlgorithm = KeyEncryptionAlgorithms.ECDH_ES_A128KW_ALG_ID;
                break;
            case 32: 
                keyEncryptionAlgorithm = KeyEncryptionAlgorithms.ECDH_ES_A256KW_ALG_ID;
                break;
            default: 
                keyEncryptionAlgorithm = KeyEncryptionAlgorithms.ECDH_ES_ALG_ID;
                break;
            }
        }
        if (keyEncryptionAlgorithm == KeyEncryptionAlgorithms.RSA_OAEP_256_ALG_ID &&
            contentEncryptionAlgorithm == ContentEncryptionAlgorithms.A128GCM_ALG_ID) {
            keyEncryptionAlgorithm = KeyEncryptionAlgorithms.RSA_OAEP_ALG_ID;
        }
        JSONX509Encrypter encrypter = new JSONX509Encrypter(getCertificatePath(keyType),
                                                            keyEncryptionAlgorithm);
        JSONCryptoHelper.Options options = 
                new JSONCryptoHelper.Options()
                    .setPublicKeyOption(JSONCryptoHelper.PUBLIC_KEY_OPTIONS.CERTIFICATE_PATH);
        String fileSuffix = "cer.json";
        byte[] encryptedData =
               JSONObjectWriter.createEncryptionObject(dataToBeEncrypted, 
                                                       contentEncryptionAlgorithm,
                                                       encrypter).serializeToBytes(JSONOutputFormats.PRETTY_PRINT);
        optionalUpdate(keyType + "#" + keyEncryptionAlgorithm.getJoseAlgorithmId().toLowerCase() + 
                           "@" + contentEncryptionAlgorithm.getJoseAlgorithmId().toLowerCase() + "@" + fileSuffix,
                       encryptedData,
                       new LocalDecrypt() {
        
                           @Override
                           public byte[] decrypt(JSONObjectReader reader) throws Exception {
                               return reader.getEncryptionObject(options).getDecryptedData(keyPair.getPrivate());
                           }
            
                       });
    }

    static void coreSymmEnc(int keyBits, 
                            String fileSuffix, 
                            ContentEncryptionAlgorithms contentEncryptionAlgorithm, 
                            boolean wantKeyId) throws Exception {
        byte[] key = symmetricKeys.getValue(keyBits);
        String keyName = symmetricKeys.getName(keyBits);
        JSONSymKeyEncrypter encrypter = new JSONSymKeyEncrypter(key);
        JSONCryptoHelper.Options options =
                new JSONCryptoHelper.Options()
                    .setPublicKeyOption(JSONCryptoHelper.PUBLIC_KEY_OPTIONS.PLAIN_ENCRYPTION);
        if (wantKeyId) {
            encrypter.setKeyId(keyName);
            options.setKeyIdOption(JSONCryptoHelper.KEY_ID_OPTIONS.REQUIRED);
        }
        byte[] encryptedData = 
                JSONObjectWriter.createEncryptionObject(dataToBeEncrypted, 
                                                        contentEncryptionAlgorithm,
                                                        encrypter).serializeToBytes(JSONOutputFormats.PRETTY_PRINT);
        optionalUpdate("a" + keyBits + "@" + contentEncryptionAlgorithm.getJoseAlgorithmId().toLowerCase() + "@" + fileSuffix,
                       encryptedData,
                       new LocalDecrypt() {
         
                           @Override
                           public byte[] decrypt(JSONObjectReader reader) throws Exception {
                               return reader.getEncryptionObject(options).getDecryptedData(key);
                           }
             
                       });
    }

    static void symmEnc(int keyBits, ContentEncryptionAlgorithms contentEncryptionAlgorithm) throws Exception {
        coreSymmEnc(keyBits, "kid.json", contentEncryptionAlgorithm, true);
    }
    
    static KeyPair readJwk(String keyType) throws Exception {
        JSONObjectReader jwkPlus = JSONParser.parse(ArrayUtil.readFile(baseKey + keyType + "privatekey.jwk"));
        // Note: The built-in JWK decoder does not accept "kid" since it doesn't have a meaning in JSF or JEF. 
        if ((keyId = jwkPlus.getStringConditional("kid")) != null) {
            jwkPlus.removeProperty("kid");
        }
        return jwkPlus.getKeyPair();
    }

    static void coreAsymEnc(String keyType, 
                            String fileSuffix,
                            ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                            boolean wantKeyId,
                            boolean wantPublicKey,
                            JSONCryptoHelper.ExtensionHolder extensionHolder,
                            JSONObjectWriter extensions) throws Exception {
        KeyPair keyPair = readJwk(keyType);
        KeyEncryptionAlgorithms keyEncryptionAlgorithm = KeyEncryptionAlgorithms.RSA_OAEP_256_ALG_ID;
        if (!(keyPair.getPublic() instanceof RSAKey)) {
            switch (contentEncryptionAlgorithm.getKeyLength()) {
            case 16: 
                keyEncryptionAlgorithm = KeyEncryptionAlgorithms.ECDH_ES_A128KW_ALG_ID;
                break;
            case 32: 
                keyEncryptionAlgorithm = KeyEncryptionAlgorithms.ECDH_ES_A256KW_ALG_ID;
                break;
            default: 
                keyEncryptionAlgorithm = KeyEncryptionAlgorithms.ECDH_ES_ALG_ID;
                break;
            }
        }
        if (keyEncryptionAlgorithm == KeyEncryptionAlgorithms.RSA_OAEP_256_ALG_ID &&
            contentEncryptionAlgorithm == ContentEncryptionAlgorithms.A128GCM_ALG_ID) {
            keyEncryptionAlgorithm = KeyEncryptionAlgorithms.RSA_OAEP_ALG_ID;
        }
        JSONAsymKeyEncrypter encrypter = new JSONAsymKeyEncrypter(keyPair.getPublic(),
                                                                  keyEncryptionAlgorithm);
        JSONCryptoHelper.Options options = new JSONCryptoHelper.Options();
        if (extensionHolder != null) {
            options.setPermittedExtensions(extensionHolder);
            encrypter.setExtensions(extensions);
        }
        encrypter.setOutputPublicKeyInfo(wantPublicKey);
        if (!wantPublicKey) {
            options.setPublicKeyOption(JSONCryptoHelper.PUBLIC_KEY_OPTIONS.FORBIDDEN);
        }
        if (wantKeyId) {
            encrypter.setKeyId(keyId);
            options.setKeyIdOption(JSONCryptoHelper.KEY_ID_OPTIONS.REQUIRED);
        }
        byte[] encryptedData =
               JSONObjectWriter.createEncryptionObject(dataToBeEncrypted, 
                                                       contentEncryptionAlgorithm,
                                                       encrypter).serializeToBytes(JSONOutputFormats.PRETTY_PRINT);
        optionalUpdate(keyType + "#" +  keyEncryptionAlgorithm.getJoseAlgorithmId().toLowerCase() + 
                           "@" + contentEncryptionAlgorithm.getJoseAlgorithmId().toLowerCase() + "@" + fileSuffix,
                       encryptedData,
                       new LocalDecrypt() {
          
                           @Override
                           public byte[] decrypt(JSONObjectReader reader) throws Exception {
                               return reader.getEncryptionObject(options).getDecryptedData(keyPair.getPrivate());
                           }
              
                       });
     }

    static void asymEnc(String keyType, 
                        ContentEncryptionAlgorithms contentEncryptionAlgorithm) throws Exception {
        coreAsymEnc(keyType,
                    "jwk.json",
                    contentEncryptionAlgorithm,
                    false,
                    true,
                    null,
                    null);
    }

    static void asymEncNoPublicKeyInfo(String keyType,
                                       ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                                       boolean wantKeyId) throws Exception {
        coreAsymEnc(keyType, 
                    wantKeyId ? "kid.json" : "imp.json",
                    contentEncryptionAlgorithm,
                    wantKeyId,
                    false,
                    null,
                    null);
    }

    static void multipleAsymEnc(String[] keyTypes, 
                                ContentEncryptionAlgorithms contentEncryptionAlgorithm, 
                                boolean wantKeyId) throws Exception {
        ArrayList<JSONDecryptionDecoder.DecryptionKeyHolder> decryptionKeys = new ArrayList<>();
        ArrayList<JSONEncrypter> encrypters = new ArrayList<>();
        String algList = "";
        for (String keyType : keyTypes) {
            KeyPair keyPair = readJwk(keyType);
            KeyEncryptionAlgorithms keyEncryptionAlgorithm = KeyEncryptionAlgorithms.RSA_OAEP_256_ALG_ID;
            if (!(keyPair.getPublic() instanceof RSAKey)) {
                switch (contentEncryptionAlgorithm.getKeyLength()) {
                case 16: 
                    keyEncryptionAlgorithm = KeyEncryptionAlgorithms.ECDH_ES_A128KW_ALG_ID;
                    break;
                default: 
                case 32: 
                    keyEncryptionAlgorithm = KeyEncryptionAlgorithms.ECDH_ES_A256KW_ALG_ID;
                    break;
                }
            }
            if (keyEncryptionAlgorithm == KeyEncryptionAlgorithms.RSA_OAEP_256_ALG_ID &&
                contentEncryptionAlgorithm == ContentEncryptionAlgorithms.A128GCM_ALG_ID) {
                keyEncryptionAlgorithm = KeyEncryptionAlgorithms.RSA_OAEP_ALG_ID;
            }
            decryptionKeys.add(new JSONDecryptionDecoder.DecryptionKeyHolder(keyPair.getPublic(),
                                                                             keyPair.getPrivate(),
                                                                             keyEncryptionAlgorithm,
                                                                             keyId));
            JSONAsymKeyEncrypter encrypter = new JSONAsymKeyEncrypter(keyPair.getPublic(),
                                                                      keyEncryptionAlgorithm);
            if (wantKeyId) {
                encrypter.setKeyId(keyId).setOutputPublicKeyInfo(false);
            }
            if (algList.length() > 0) {
                algList += ",";
            }
            algList += keyType + "#" + keyEncryptionAlgorithm.getJoseAlgorithmId().toLowerCase();
            encrypters.add(encrypter);
        }
        JSONCryptoHelper.Options options = new JSONCryptoHelper.Options();
        String fileSuffix = "mult-jwk.json"; 
        if (wantKeyId) {
            fileSuffix = "mult-kid.json"; 
            options.setKeyIdOption(JSONCryptoHelper.KEY_ID_OPTIONS.REQUIRED);
            options.setPublicKeyOption(JSONCryptoHelper.PUBLIC_KEY_OPTIONS.FORBIDDEN);
        }
        byte[] encryptedData =
               JSONObjectWriter.createEncryptionObjects(dataToBeEncrypted, 
                                                        contentEncryptionAlgorithm,
                                                        encrypters).serializeToBytes(JSONOutputFormats.PRETTY_PRINT);
        String baseName = algList + "@" + contentEncryptionAlgorithm.getJoseAlgorithmId().toLowerCase() + "@" + fileSuffix;
        String fileName = baseEncryption + baseName;
        int q = 0;
        JSONObjectReader newEncryptedData = JSONParser.parse(encryptedData);
        for (JSONDecryptionDecoder decoder : newEncryptedData.getEncryptionObjects(options)) {
            q++;
            if (!ArrayUtil.compare(decoder.getDecryptedData(decryptionKeys), dataToBeEncrypted)) {
                throw new Exception("Dec err");
            }
        }
        if (q != keyTypes.length) {
            throw new IOException("Wrong number of recipients");
        }
        boolean changed = true;
        options = new JSONCryptoHelper.Options();
        if (wantKeyId) {
            options.setKeyIdOption(JSONCryptoHelper.KEY_ID_OPTIONS.REQUIRED);
            options.setPublicKeyOption(JSONCryptoHelper.PUBLIC_KEY_OPTIONS.FORBIDDEN);
        }
        try {
            JSONObjectReader oldEncryptedData = JSONParser.parse(ArrayUtil.readFile(fileName));
            boolean allOk = true;
            for (JSONDecryptionDecoder decoder : oldEncryptedData.getEncryptionObjects(options)) {
                if (!ArrayUtil.compare(decoder.getDecryptedData(decryptionKeys), dataToBeEncrypted)) {
                    allOk = false;
                    break;
                }
            }
            if (allOk) {
                // All good but are the new and old effectively the same?
                if (cleanEncryption(newEncryptedData).equals(cleanEncryption(oldEncryptedData))) {
                    return;  // Yes, don't rewrite.
                }
            }
        } catch (Exception  e) {
            changed = false;  // New I guess
        }
        if (changed) {
            System.out.println("UPDATED: " + baseName);
        }
        ArrayUtil.writeFile(fileName, encryptedData);
    }
}