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
package org.webpki.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import java.security.interfaces.ECKey;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.NamedParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import org.webpki.util.ArrayUtil;

/**
 * Core JOSE and COSE encryption support.
 *<p>
 * Implements a subset of the RFC 7516 (JWE) and RFC 8152 (COSE) algorithms.
 * </p>
 */

// Source configured for JDK.

public class EncryptionCore {

    /**
     * Return object for symmetric key encryptions.
     */
    public static class SymmetricEncryptionResult {
        byte[] tag;
        byte[] cipherText;

        SymmetricEncryptionResult(byte[] tag, byte[] cipherText) {
            this.tag = tag;
            this.cipherText = cipherText;
        }

        public byte[] getTag() {
            return tag;
        }

        public byte[] getCipherText() {
            return cipherText;
        }
    }

    /**
     * Return object for ECDH and RSA encryptions.
     */
    public static class AsymmetricEncryptionResult {

        private byte[] contentEncryptionKey;
        private byte[] encryptedKey;
        private PublicKey ephemeralKey;

        AsymmetricEncryptionResult(byte[] contentEncryptionKey,
                                   byte[] encryptedKey,
                                   PublicKey ephemeralKey) {
            this.contentEncryptionKey = contentEncryptionKey;
            this.encryptedKey = encryptedKey;
            this.ephemeralKey = ephemeralKey;
        }

        public byte[] getContentEncryptionKey() {
            return contentEncryptionKey;
        }

        public byte[] getEncryptedKey() {
            return encryptedKey;
        }

        public PublicKey getEphemeralKey() {
            return ephemeralKey;
        }
    }
    
    private EncryptionCore() {} // Static and final class
    
    // AES CBC static
    static final int    AES_CBC_IV_LENGTH   = 16; 
    static final String AES_CBC_JCENAME     = "AES/CBC/PKCS5Padding";

    // AES GCM static
    static final int    AES_GCM_IV_LENGTH   = 12;
    static final int    AES_GCM_TAG_LENGTH  = 16;
    static final String AES_GCM_JCENAME     = "AES/GCM/NoPadding";

    // AES Key Wrap static
    static final String AES_KEY_WRAP_JCENAME = "AESWrap";

    // NIST Concat KDF and HKDF static
    static final String HASH_DIGEST_JCENAME  = "SHA-256";
    static final String HMAC_DIGEST_JCENAME  = "HMACSHA256";
    static final int    KDF_DIGEST_LENGTH    = 32;
    static final byte[] HKDF_NO_SALT         = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    
    // RSA OAEP
    static final String RSA_OAEP_JCENAME     = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    static final String RSA_OAEP_256_JCENAME = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    private static String aesProviderName;

    /**
     * Explicitly set provider for AES operations.
     * @param providerName Name of provider
     */
    public static void setAesProvider(String providerName) {
        aesProviderName = providerName;
    }
    
    private static String ecProviderName;
    
    /**
     * Explicitly set provider for EC operations.
     * @param providerName Name of provider
     */
    public static void setEcProvider(String providerName) {
        ecProviderName = providerName;
    }

    private static String rsaProviderName;
    
    /**
     * Explicitly set provider for RSA operations.
     * @param providerName Name of provider
     */
    public static void setRsaProvider(String providerName) {
        rsaProviderName = providerName;
    }

    private static Cipher getAesCipher(String algorithm) throws GeneralSecurityException {
        return aesProviderName == null ? 
            Cipher.getInstance(algorithm) 
                                       : 
            Cipher.getInstance(algorithm, aesProviderName);
    }

    private static byte[] getTag(byte[] key,
                                 byte[] cipherText,
                                 byte[] iv,
                                 byte[] authData,
                                 ContentEncryptionAlgorithms contentEncryptionAlgorithm) 
    throws GeneralSecurityException {
        int tagLength = contentEncryptionAlgorithm.tagLength;
        byte[] al = new byte[8];
        int value = authData.length * 8;
        for (int q = 24, i = 4; q >= 0; q -= 8, i++) {
            al[i] = (byte) (value >>> q);
        }
        Mac mac = Mac.getInstance(contentEncryptionAlgorithm.jceNameOfTagHmac);
        mac.init(new SecretKeySpec(key, 0, tagLength, "RAW"));
        mac.update(authData);
        mac.update(iv);
        mac.update(cipherText);
        mac.update(al);
        byte[] tag = new byte[tagLength];
        System.arraycopy(mac.doFinal(), 0, tag, 0, tagLength);
        return tag;
    }
    
    private static byte[] aesCbcCore(int mode, 
                                     byte[] key, 
                                     byte[] iv, 
                                     byte[] data, 
                                     ContentEncryptionAlgorithms contentEncryptionAlgorithm)
    throws GeneralSecurityException {
        Cipher cipher = getAesCipher(AES_CBC_JCENAME);
        int aesKeyLength = contentEncryptionAlgorithm.keyLength / 2;
        cipher.init(mode,
                    new SecretKeySpec(key, aesKeyLength, aesKeyLength, "AES"),
                    new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    private static byte[] aesGcmCore(int mode, byte[] key, byte[] iv, byte[] authData, byte[] data)
    throws GeneralSecurityException {
        Cipher cipher = getAesCipher(AES_GCM_JCENAME);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(AES_GCM_TAG_LENGTH * 8, iv);
        cipher.init(mode,
                    new SecretKeySpec(key, "AES"),
                    gcmSpec);
        cipher.updateAAD(authData);
        return cipher.doFinal(data);
    }

    private static void check(byte[] parameter,
                              String parameterName,
                              int expectedLength,
                              ContentEncryptionAlgorithms contentEncryptionAlgorithm)
            throws GeneralSecurityException {
        if (parameter == null) {
            throw new GeneralSecurityException("Parameter \"" + parameterName +
                                               "\"=null for " +
                                               contentEncryptionAlgorithm.toString());
        }
        if (parameter.length != expectedLength) {
            throw new GeneralSecurityException("Incorrect parameter \"" + parameterName +
                                               "\" length (" + parameter.length + ") for " +
                                               contentEncryptionAlgorithm.toString());
        }
    }
 
    public static byte[] createIv(ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
        return CryptoRandom.generateRandom(contentEncryptionAlgorithm.ivLength);
    }

    /**
     * Perform a symmetric key encryption.
     * @param contentEncryptionAlgorithm Encryption algorithm
     * @param key Encryption key
     * @param iv Initialization vector
     * @param plainText Data to be encrypted
     * @param authData Additional input factor for authentication
     * @return A composite object including encrypted data
     * @throws GeneralSecurityException
     */
    public static SymmetricEncryptionResult 
            contentEncryption(ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                              byte[] key,
                              byte[] iv,
                              byte[] plainText,
                              byte[] authData) throws GeneralSecurityException {
        check(key, "key", contentEncryptionAlgorithm.keyLength, contentEncryptionAlgorithm);
        if (contentEncryptionAlgorithm.gcm) {
            byte[] cipherOutput = aesGcmCore(Cipher.ENCRYPT_MODE, key, iv, authData, plainText);
            int tagPos = cipherOutput.length - AES_GCM_TAG_LENGTH;
            byte[] cipherText = ArrayUtil.copy(cipherOutput, tagPos);
            byte[] tag = new byte[AES_GCM_TAG_LENGTH];
            System.arraycopy(cipherOutput, tagPos, tag, 0, AES_GCM_TAG_LENGTH);
            return new SymmetricEncryptionResult(tag, cipherText);
        }
        byte[] cipherText = aesCbcCore(Cipher.ENCRYPT_MODE,
                                       key,
                                       iv, 
                                       plainText, 
                                       contentEncryptionAlgorithm);
        return new SymmetricEncryptionResult(getTag(key, 
                                                    cipherText, 
                                                    iv,
                                                    authData, 
                                                    contentEncryptionAlgorithm), 
                                              cipherText);
    }

    /**
     * Decrypt using a symmetric key.
     * @param contentEncryptionAlgorithm Encryption algorithm
     * @param key Encryption key
     * @param cipherText Encrypted data
     * @param iv Initialization Vector
     * @param authData Additional input used for authentication purposes
     * @param tag Authentication tag
     * @return Decrypted data
     * @throws GeneralSecurityException
     */
    public static byte[] contentDecryption(ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                                           byte[] key,
                                           byte[] cipherText,
                                           byte[] iv,
                                           byte[] authData,
                                           byte[] tag) throws GeneralSecurityException {
        check(key, "key", contentEncryptionAlgorithm.keyLength, contentEncryptionAlgorithm);
        check(iv, "iv", contentEncryptionAlgorithm.ivLength, contentEncryptionAlgorithm);
        check(tag, "tag", contentEncryptionAlgorithm.tagLength, contentEncryptionAlgorithm);
        if (contentEncryptionAlgorithm.gcm) {
            return aesGcmCore(Cipher.DECRYPT_MODE, 
                              key, 
                              iv, 
                              authData, 
                              ArrayUtil.add(cipherText, tag));
        }
        if (!ArrayUtil.compare(tag, getTag(key, 
                                           cipherText,
                                           iv, 
                                           authData,
                                           contentEncryptionAlgorithm))) {
            throw new GeneralSecurityException("Authentication error on algorithm: " + 
                                               contentEncryptionAlgorithm.toString());
        }
        return aesCbcCore(Cipher.DECRYPT_MODE, 
                          key, 
                          iv, 
                          cipherText, 
                          contentEncryptionAlgorithm);
    }

    private static byte[] rsaCore(int mode,
                                  Key key,
                                  byte[] data,
                                  KeyEncryptionAlgorithms keyEncryptionAlgorithm)
    throws GeneralSecurityException {
        if (!keyEncryptionAlgorithm.rsa) {
            throw new GeneralSecurityException(
                    "Unsupported RSA algorithm: " + keyEncryptionAlgorithm);
        }
        String jceName = keyEncryptionAlgorithm == KeyEncryptionAlgorithms.RSA_OAEP ?
                RSA_OAEP_JCENAME : RSA_OAEP_256_JCENAME;
        Cipher cipher = rsaProviderName == null ? 
                Cipher.getInstance(jceName)
                                                : 
                Cipher.getInstance(jceName, rsaProviderName);
        if (keyEncryptionAlgorithm == KeyEncryptionAlgorithms.RSA_OAEP_256) {
            cipher.init(mode, key, new OAEPParameterSpec("SHA-256", "MGF1",
                    MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        } else {
            cipher.init(mode, key);
        }
        return cipher.doFinal(data);
    }

    /**
     * Perform an RSA encrypt key operation.
     * @param contentEncryptionKey Also known as CEK
     * @param keyEncryptionAlgorithm The RSA encryption algorithm
     * @param publicKey The receiver's (usually static) public key
     * @return A composite object including the (plain text) data encryption key
     * @throws GeneralSecurityException
     */
    public static AsymmetricEncryptionResult rsaEncryptKey(
            byte[] contentEncryptionKey,
            KeyEncryptionAlgorithms keyEncryptionAlgorithm,
            PublicKey publicKey) throws GeneralSecurityException {
        return new AsymmetricEncryptionResult(contentEncryptionKey,
                                              rsaCore(Cipher.ENCRYPT_MODE,
                                                      publicKey,
                                                      contentEncryptionKey,
                                                      keyEncryptionAlgorithm),
                                              null);
    }

    /**
     * Decrypt a symmetric key using an RSA cipher.
     * @param keyEncryptionAlgorithm The algorithm to use
     * @param encryptedKey Contains a symmetric key used for encrypting the data
     * @param privateKey The RSA private key
     * @return The key in plain text
     * @throws GeneralSecurityException
     */
    public static byte[] rsaDecryptKey(KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                       byte[] encryptedKey,
                                       PrivateKey privateKey) 
    throws GeneralSecurityException {
        return rsaCore(Cipher.DECRYPT_MODE,
                       privateKey,
                       encryptedKey,
                       keyEncryptionAlgorithm);
    }

    public static byte[] hmacKdf(byte[] ikm, byte[] salt, byte[] info, int keyLength) 
            throws IOException, GeneralSecurityException {
        final Mac hmac = Mac.getInstance(HMAC_DIGEST_JCENAME);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int reps = (keyLength + KDF_DIGEST_LENGTH - 1) / KDF_DIGEST_LENGTH;

        // HKDF according to RFC 5869 but not equivalent to COSE
        
        // 1. Extract
        if (salt == null || salt.length == 0) {
            salt = HKDF_NO_SALT;
        }
        hmac.init(new SecretKeySpec(salt, "RAW"));
        byte[] prk = hmac.doFinal(ikm);
        
        // 2. Expand
        byte[] t = new byte[0];
        for (int i = 1; i <= reps; i++) {
            hmac.reset();
            hmac.init(new SecretKeySpec(prk, "RAW"));
            hmac.update(t);
            hmac.update(info);
            hmac.update((byte)i);
            t = hmac.doFinal();
            baos.write(t);
        }

        // Only use as much of the digest that is asked for
        byte[] okm = new byte[keyLength];
        System.arraycopy(baos.toByteArray(), 0, okm, 0, keyLength);
        return okm;
    }

    private static void addInt4(MessageDigest messageDigest, int value) {
        for (int i = 24; i >= 0; i -= 8) {
            messageDigest.update((byte) (value >>> i));
        }
    }

    public static byte[] concatKdf(byte[] secret, String joseAlgorithmId, int keyLength) 
            throws IOException, GeneralSecurityException {
        byte[] algorithmId = joseAlgorithmId.getBytes("utf-8");
        final MessageDigest messageDigest = MessageDigest.getInstance(HASH_DIGEST_JCENAME);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int reps = (keyLength + KDF_DIGEST_LENGTH - 1) / KDF_DIGEST_LENGTH;

        // Concat KDF according to JWA
        for (int i = 1; i <= reps; i++) {
            // Round indicator
            addInt4(messageDigest, i);
            // Z
            messageDigest.update(secret);
            // AlgorithmID = Content encryption algorithm
            addInt4(messageDigest, algorithmId.length);
            messageDigest.update(algorithmId);
            // PartyUInfo = Empty as described in the JEF specification
            addInt4(messageDigest, 0);
            // PartyVInfo = Empty as described in the JEF specification
            addInt4(messageDigest, 0);
            // SuppPubInfo = Key length in bits
            addInt4(messageDigest, keyLength * 8);
            baos.write(messageDigest.digest());
        }

        // Only use as much of the digest that is asked for
        byte[] result = new byte[keyLength];
        System.arraycopy(baos.toByteArray(), 0, result, 0, keyLength);
        return result;
    }    

    private static byte[] coreKeyAgreement(boolean coseMode,
                                           KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                           ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                                           PublicKey receivedPublicKey,
                                           PrivateKey privateKey)
    throws GeneralSecurityException, IOException {
        // Begin by calculating Z (do the DH)
        String jceName = privateKey instanceof ECKey ? "ECDH" : "XDH";
        KeyAgreement keyAgreement = ecProviderName == null ?
                KeyAgreement.getInstance(jceName) 
                                   : 
                KeyAgreement.getInstance(jceName, ecProviderName);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(receivedPublicKey, true);
        byte[] Z = keyAgreement.generateSecret();
        int keyLength = keyEncryptionAlgorithm.keyWrap ?
                keyEncryptionAlgorithm.keyEncryptionKeyLength 
                                                       : 
                contentEncryptionAlgorithm.keyLength;
        if (coseMode) {
            int coseAlg = keyEncryptionAlgorithm.coseId;
            return hmacKdf(Z,
                           null,
                           new byte[] {(byte)(coseAlg >> 24),
                                       (byte)(coseAlg >> 16),
                                       (byte)(coseAlg >> 8),
                                       (byte)coseAlg},
                           keyLength);
        }
        return concatKdf(Z,
                         (keyEncryptionAlgorithm.keyWrap ?
                              keyEncryptionAlgorithm.joseId 
                                                         : 
                              contentEncryptionAlgorithm.joseId),
                         keyLength);
    }

    /**
     * Perform a receiver side ECDH operation.

     * @param coseMode True => hmacKdf, else concatKdf
     * @param keyEncryptionAlgorithm The ECDH algorithm
     * @param contentEncryptionAlgorithm The designated content encryption algorithm
     * @param receivedPublicKey The sender's (usually ephemeral) public key
     * @param privateKey The receiver's private key
     * @param encryptedKey For ECDH+KW based operations only
     * @return Shared secret
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public static byte[] receiverKeyAgreement(
            boolean coseMode,
            KeyEncryptionAlgorithms keyEncryptionAlgorithm,
            ContentEncryptionAlgorithms contentEncryptionAlgorithm,
            PublicKey receivedPublicKey,
            PrivateKey privateKey,
            byte[] encryptedKey) throws GeneralSecurityException, IOException {
        // Sanity check
        if (keyEncryptionAlgorithm.keyWrap ^ (encryptedKey != null)) {
            throw new GeneralSecurityException("\"encryptedKey\" must " + 
                    (encryptedKey == null ? "not be null" : "be null") + " for algorithm: " +
                    keyEncryptionAlgorithm.toString());
        }
        byte[] derivedKey = coreKeyAgreement(coseMode,
                                             keyEncryptionAlgorithm,
                                             contentEncryptionAlgorithm,
                                             receivedPublicKey,
                                             privateKey);
        if (keyEncryptionAlgorithm.keyWrap) {
            Cipher cipher = getAesCipher(AES_KEY_WRAP_JCENAME);
            cipher.init(Cipher.UNWRAP_MODE, new SecretKeySpec(derivedKey, "AES"));
            derivedKey = cipher.unwrap(encryptedKey, "AES", Cipher.SECRET_KEY).getEncoded();
        }
        return derivedKey;
    }

    /**
     * Perform a sender side ECDH operation.
     * 
     * @param coseMode True => hmacKdf, else concatKdf
     * @param contentEncryptionKey Also known as CEK
     * @param keyEncryptionAlgorithm The ECDH algorithm
     * @param contentEncryptionAlgorithm The designated content encryption algorithm
     * @param staticKey The receiver's (usually static) public key
     * @return A composite object including the (plain text) data encryption key
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public static AsymmetricEncryptionResult
            senderKeyAgreement(boolean coseMode,
                               byte[] contentEncryptionKey,
                               KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                               ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                               PublicKey staticKey) 
    throws IOException, GeneralSecurityException {
        AlgorithmParameterSpec paramSpec; 
        KeyPairGenerator generator;
        if (staticKey instanceof ECKey) {
            paramSpec = new ECGenParameterSpec(
                    KeyAlgorithms.getKeyAlgorithm(staticKey).getJceName());
            generator = ecProviderName == null ?
                    KeyPairGenerator.getInstance("EC") 
                                              : 
                    KeyPairGenerator.getInstance("EC", ecProviderName);
        } else {
            paramSpec = new NamedParameterSpec(
                    OkpSupport.getKeyAlgorithm(staticKey).getJceName());
            generator = ecProviderName == null ?
                    KeyPairGenerator.getInstance("XDH") 
                                              : 
                    KeyPairGenerator.getInstance("XDH", ecProviderName);
        }
        generator.initialize(paramSpec, new SecureRandom());
        KeyPair keyPair = generator.generateKeyPair();
        byte[] derivedKey = coreKeyAgreement(coseMode,
                                             keyEncryptionAlgorithm,
                                             contentEncryptionAlgorithm,
                                             staticKey,
                                             keyPair.getPrivate());
        byte[] encryptedKey = null;
        if (keyEncryptionAlgorithm.keyWrap) {
            Cipher cipher = getAesCipher(AES_KEY_WRAP_JCENAME);
            cipher.init(Cipher.WRAP_MODE, new SecretKeySpec(derivedKey, "AES"));
            encryptedKey = cipher.wrap(new SecretKeySpec(contentEncryptionKey, "AES"));
            derivedKey = contentEncryptionKey;
        }
        return new AsymmetricEncryptionResult(derivedKey, 
                                              encryptedKey,
                                              keyPair.getPublic());
    }
}
