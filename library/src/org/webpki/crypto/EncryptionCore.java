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

import java.util.Arrays;

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

// Source configured for JDK.

/**
 * Core JOSE and COSE encryption support.
 *<p>
 * Implements a subset of the RFC 7516 (JWE) and RFC 8152 (COSE) algorithms.
 * </p>
 */
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
    static final String RSA_OAEP_JCENAME     = "RSA/ECB/OAEPPadding";

    private static String aesProviderName;

    /**
     * Explicitly set provider for AES operations.
     * @param providerName Name of provider
     */
    public static void setAesProvider(String providerName) {
        aesProviderName = providerName;
    }
    
    private static String ecStaticProvider;
    private static String ecEphemeralProvider;
    
    /**
     * Explicitly set provider for ECDH operations.
     * <p>
     * Setting <code>ecStaticProviderName</code> to <code>"AndroidKeystore"</cde>
     * permits <i>decryption</i> using HSM protected keys.
     * </p>
     * <p>
     * Setting <code>ecEphemeralProviderName</code> to anything but <code>null</code>
     * should be done with caution.
     * </p>
     * @param ecStaticProviderName Name of provider for static private keys
     * @param ecEphemeralProviderName Name of provider for ephemeral private keys
     */
    public static void setEcProvider(String ecStaticProviderName, 
                                     String ecEphemeralProviderName) {
        ecStaticProvider = ecStaticProviderName;
        ecEphemeralProvider = ecEphemeralProviderName;
    }

    private static String rsaProvider;
    
    /**
     * Explicitly set provider for RSA operations.
     * @param rsaProviderName Name of provider
     */
    public static void setRsaProvider(String rsaProviderName) {
        rsaProvider = rsaProviderName;
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
                              ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
        if (parameter == null) {
            throw new CryptoException("Parameter \"" + parameterName +
                                      "\"=null for " +
                                      contentEncryptionAlgorithm.toString());
        }
        if (parameter.length != expectedLength) {
            throw new CryptoException("Incorrect parameter \"" + parameterName +
                                      "\" length (" + parameter.length + ") for " +
                                      contentEncryptionAlgorithm.toString());
        }
    }
 
   /**
    * Create an IV with an algorithm specific length.
    * 
    * @param contentEncryptionAlgorithm
    * @return
    */
    public static byte[] createIv(ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
        return CryptoRandom.generateRandom(contentEncryptionAlgorithm.ivLength);
    }

    /**
     * Perform a symmetric key encryption.
     * 
     * @param contentEncryptionAlgorithm Encryption algorithm
     * @param key Encryption key
     * @param iv Initialization vector
     * @param plainText Data to be encrypted
     * @param authData Additional input factor for authentication
     * @return A composite object including encrypted data
     */
    public static SymmetricEncryptionResult 
            contentEncryption(ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                              byte[] key,
                              byte[] iv,
                              byte[] plainText,
                              byte[] authData) {
        check(key, "key", contentEncryptionAlgorithm.keyLength, contentEncryptionAlgorithm);
        try {
            if (contentEncryptionAlgorithm.gcm) {
                byte[] cipherOutput = aesGcmCore(Cipher.ENCRYPT_MODE, key, iv, authData, plainText);
                int tagPos = cipherOutput.length - AES_GCM_TAG_LENGTH;
                byte[] cipherText = Arrays.copyOf(cipherOutput, tagPos);
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
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        }
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
     */
    public static byte[] contentDecryption(ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                                           byte[] key,
                                           byte[] cipherText,
                                           byte[] iv,
                                           byte[] authData,
                                           byte[] tag) {
        check(key, "key", contentEncryptionAlgorithm.keyLength, contentEncryptionAlgorithm);
        check(iv, "iv", contentEncryptionAlgorithm.ivLength, contentEncryptionAlgorithm);
        check(tag, "tag", contentEncryptionAlgorithm.tagLength, contentEncryptionAlgorithm);
        try {
            if (contentEncryptionAlgorithm.gcm) {
                byte[] totalData = Arrays.copyOf(cipherText, cipherText.length + tag.length);
                System.arraycopy(tag, 0, totalData, cipherText.length, tag.length);
                return aesGcmCore(Cipher.DECRYPT_MODE,
                                  key, 
                                  iv, 
                                  authData,
                                  totalData);
            }
            if (!Arrays.equals(tag, getTag(key, 
                                           cipherText,
                                           iv, 
                                           authData,
                                           contentEncryptionAlgorithm))) {
                throw new CryptoException("Authentication error on algorithm: " + 
                                          contentEncryptionAlgorithm.toString());
            }
            return aesCbcCore(Cipher.DECRYPT_MODE, 
                              key, 
                              iv, 
                              cipherText, 
                              contentEncryptionAlgorithm);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        }
    }

    static byte[] rsaCore(int mode,
                          Key key,
                          byte[] data,
                          KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                          String provider) {
        try {
            if (!keyEncryptionAlgorithm.rsa) {
                throw new CryptoException(
                        "Unsupported RSA algorithm: " + keyEncryptionAlgorithm);
            }
            Cipher cipher = provider == null ? 
                    Cipher.getInstance(RSA_OAEP_JCENAME)
                                             : 
                    Cipher.getInstance(RSA_OAEP_JCENAME, provider);
            cipher.init(mode, key, new OAEPParameterSpec("SHA-256", "MGF1",
                        keyEncryptionAlgorithm == KeyEncryptionAlgorithms.RSA_OAEP_256 ?
                            MGF1ParameterSpec.SHA256 : MGF1ParameterSpec.SHA1, 
                            PSource.PSpecified.DEFAULT));
            return cipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        }
    }

    /**
     * Perform an RSA encrypt key operation.
     * @param contentEncryptionKey Also known as CEK
     * @param keyEncryptionAlgorithm The RSA encryption algorithm
     * @param publicKey The receiver's (usually static) public key
     * @return A composite object including the (plain text) data encryption key
     */
    public static AsymmetricEncryptionResult rsaEncryptKey(
            byte[] contentEncryptionKey,
            KeyEncryptionAlgorithms keyEncryptionAlgorithm,
            PublicKey publicKey) {
        return new AsymmetricEncryptionResult(contentEncryptionKey,
                                              rsaCore(Cipher.ENCRYPT_MODE,
                                                      publicKey,
                                                      contentEncryptionKey,
                                                      keyEncryptionAlgorithm,
                                                      null),
                                              null);
    }

    /**
     * Decrypt a symmetric key using an RSA cipher.
     * @param privateKey The RSA private key
     * @param keyEncryptionAlgorithm The algorithm to use
     * @param encryptedKey Contains a symmetric key used for encrypting the data
     * @return The key in plain text
     */
    public static byte[] rsaDecryptKey(PrivateKey privateKey,
                                       KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                       byte[] encryptedKey) {
        return rsaCore(Cipher.DECRYPT_MODE,
                       privateKey,
                       encryptedKey,
                       keyEncryptionAlgorithm,
                       rsaProvider);
    }

    static byte[] hmacKdf(byte[] ikm, 
                          byte[] salt, 
                          byte[] info, 
                          int keyLength) throws IOException, GeneralSecurityException {
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
        return Arrays.copyOf(baos.toByteArray(), keyLength);
    }

    private static void addInt4(MessageDigest messageDigest, int value) {
        for (int i = 24; i >= 0; i -= 8) {
            messageDigest.update((byte) (value >>> i));
        }
    }

    static byte[] concatKdf(byte[] secret, 
                            String joseAlgorithmId, 
                            int keyLength) throws IOException, GeneralSecurityException {
        byte[] algorithmId = joseAlgorithmId.getBytes();
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
        return Arrays.copyOf(baos.toByteArray(), keyLength);
    }    

    private static byte[] coreKeyAgreement(boolean coseMode,
                                           KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                           ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                                           PublicKey receivedPublicKey,
                                           PrivateKey privateKey,
                                           String provider) throws IOException, 
                                                                   GeneralSecurityException {
        // Begin by calculating Z (do the DH)
        String jceName = privateKey instanceof ECKey ? "ECDH" : "XDH";
        KeyAgreement keyAgreement = provider == null ?
                KeyAgreement.getInstance(jceName) 
                                   : 
                KeyAgreement.getInstance(jceName, provider);
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

     * @param coseMode If <code>true</code> => <code>hmacKdf</code>, else <code>concatKdf</code>
     * @param privateKey The receiver's private key
     * @param keyEncryptionAlgorithm The ECDH algorithm
     * @param contentEncryptionAlgorithm The designated content encryption algorithm
     * @param publicKey The sender's (usually ephemeral) public key
     * @param encryptedKey For ECDH+KW based operations only
     * @return Shared secret
     */
    public static byte[] receiverKeyAgreement(
            boolean coseMode,
            PrivateKey privateKey,
            KeyEncryptionAlgorithms keyEncryptionAlgorithm,
            ContentEncryptionAlgorithms contentEncryptionAlgorithm,
            PublicKey publicKey,
            byte[] encryptedKey) {
        // Sanity check
        if (keyEncryptionAlgorithm.keyWrap ^ (encryptedKey != null)) {
            throw new CryptoException("\"encryptedKey\" must " + 
                    (encryptedKey == null ? "not be null" : "be null") + " for algorithm: " +
                    keyEncryptionAlgorithm.toString());
        }
        try {
            byte[] derivedKey = coreKeyAgreement(coseMode,
                                                 keyEncryptionAlgorithm,
                                                 contentEncryptionAlgorithm,
                                                 publicKey,
                                                 privateKey,
                                                 ecStaticProvider);
            if (keyEncryptionAlgorithm.keyWrap) {
                Cipher cipher = getAesCipher(AES_KEY_WRAP_JCENAME);
                cipher.init(Cipher.UNWRAP_MODE, new SecretKeySpec(derivedKey, "AES"));
                derivedKey = cipher.unwrap(encryptedKey, "AES", Cipher.SECRET_KEY).getEncoded();
            }
            return derivedKey;
        } catch (GeneralSecurityException | IOException e) {
            throw new CryptoException(e);
        }
    }

    /**
     * Key decryption convenience method.
     * 
     * @param coseMode <code>true</code> for COSE, <code>false</code> for JOSE
     * @param privateKey Private decryption key
     * @param optionalEncryptedKey For ECDH
     * @param optionalEphemeralKey For key-wrapping algorithms
     * @param keyEncryptionAlgorithm Key encryption algorithm
     * @param contentEncryptionAlgorithm Content encryption algorithm
     * @return Decrypted key
     */
    public static byte[] decryptKey(boolean coseMode,
                                    PrivateKey privateKey,
                                    byte[] optionalEncryptedKey,     // For all but ECDH-ES
                                    PublicKey optionalEphemeralKey,  // For ECDH*
                                    KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                    ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
        // The core
        return keyEncryptionAlgorithm.isRsa() ?
            EncryptionCore.rsaDecryptKey(privateKey,
                                         keyEncryptionAlgorithm,
                                         optionalEncryptedKey)
                                              :
            EncryptionCore.receiverKeyAgreement(coseMode,
                                                privateKey,
                                                keyEncryptionAlgorithm,
                                                contentEncryptionAlgorithm,
                                                optionalEphemeralKey,
                                                optionalEncryptedKey);
    }

    /**
     * Perform a sender side ECDH operation.
     * 
     * @param coseMode If <code>true</code> => <code>hmacKdf</code>, else <code>concatKdf</code>
     * @param contentEncryptionKey Also known as CEK
     * @param keyEncryptionAlgorithm The ECDH algorithm
     * @param contentEncryptionAlgorithm The designated content encryption algorithm
     * @param publicKey The receiver's (usually static) public key
     * @return A composite object including the (plain text) data encryption key
     */
    public static AsymmetricEncryptionResult
            senderKeyAgreement(boolean coseMode,
                               byte[] contentEncryptionKey,
                               KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                               ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                               PublicKey publicKey) {
        try {
        KeyPairGenerator generator;
        AlgorithmParameterSpec paramSpec; 
        if (publicKey instanceof ECKey) {
            paramSpec = new ECGenParameterSpec(
                    KeyAlgorithms.getKeyAlgorithm(publicKey).getJceName());
            generator = ecEphemeralProvider == null ?
                    KeyPairGenerator.getInstance("EC") 
                                              : 
                    KeyPairGenerator.getInstance("EC", ecEphemeralProvider);
        } else {
            paramSpec = new NamedParameterSpec(
                    OkpSupport.getKeyAlgorithm(publicKey).getJceName());
            generator = ecEphemeralProvider == null ?
                    KeyPairGenerator.getInstance("XDH") 
                                              : 
                    KeyPairGenerator.getInstance("XDH", ecEphemeralProvider);
        }
        generator.initialize(paramSpec, new SecureRandom());
//System.out.println(generator.getProvider().getName());
        KeyPair keyPair = generator.generateKeyPair();
        byte[] derivedKey = coreKeyAgreement(coseMode,
                                             keyEncryptionAlgorithm,
                                             contentEncryptionAlgorithm,
                                             publicKey,
                                             keyPair.getPrivate(),
                                             ecEphemeralProvider);
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
        } catch (GeneralSecurityException | IOException e) {
            throw new CryptoException(e);
        }
    }
}
