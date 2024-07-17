/*
 *  Copyright 2006-2024 WebPKI.org (https://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.crypto;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.InputStream;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;

import java.util.Arrays;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.BeforeClass;
import org.junit.Test;

import org.webpki.util.Base64URL;
import org.webpki.util.HexaDecimal;
import org.webpki.util.IO;
import org.webpki.util.PEMDecoder;
import org.webpki.util.UTF8;


/**
 * ECDH tests.
 * <p>
 * ECDH is actually quite complicated due to the provider concept.
 * In practical terms: a private key used for key agreement may
 * come from different providers, depending on if the key represents
 * a static or an ephemeral key.
 * </p>
 *  
 */
public class CryptoTest {

    private static Logger logger = Logger.getLogger(CustomCryptoProvider.class.getCanonicalName());

    static final byte[] DATA_TO_ENCRYPT = 
            UTF8.encode("The quick brown fox jumps over the lazy bear");
    
    static final byte[] DATA_TO_SIGN = 
            UTF8.encode("Signatures make the world go round?");

    static final String ALT_PROVIDER = "BC";

    @BeforeClass
    public static void openFile() throws Exception {
        Provider bc = (Provider) Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider").getDeclaredConstructor().newInstance();
        if (Security.getProvider(bc.getName()) == null) {
            try {
                Security.addProvider(bc);
                logger.info("BouncyCastle successfully added to the list of providers");
            } catch (Exception e) {
                logger.log(Level.SEVERE, "BouncyCastle didn't load");
                throw new RuntimeException(e);
            }
        } else {
            throw new RuntimeException("BouncyCastle was already loaded");
        }
    }
    
    KeyPair generateKeyPair(String staticProvider, 
                            KeyAlgorithms keyAlgorithm) throws Exception {
        KeyPairGenerator generator;
        if (keyAlgorithm.getKeyType() == KeyTypes.RSA) {
            generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(keyAlgorithm.getPublicKeySizeInBits());
        } else if (keyAlgorithm.getKeyType() == KeyTypes.EC) {
            AlgorithmParameterSpec paramSpec = new ECGenParameterSpec(keyAlgorithm.getJceName());
            generator = staticProvider == null ?
                    KeyPairGenerator.getInstance("EC") 
                                              : 
                    KeyPairGenerator.getInstance("EC", staticProvider);
            generator.initialize(paramSpec, new SecureRandom());
        } else if (keyAlgorithm.getKeyType() == KeyTypes.XEC) {
            AlgorithmParameterSpec paramSpec = new NamedParameterSpec(keyAlgorithm.getJceName());
            generator = staticProvider == null ?
                    KeyPairGenerator.getInstance("XDH") 
                                               : 
                    KeyPairGenerator.getInstance("XDH", staticProvider);
            generator.initialize(paramSpec, new SecureRandom());
        } else {
            generator = staticProvider == null ?
                    KeyPairGenerator.getInstance(keyAlgorithm.getJceName()) 
                                               : 
                    KeyPairGenerator.getInstance(keyAlgorithm.getJceName(), staticProvider);
        }
        return generator.generateKeyPair();
    }

    private void asymEncryptionOneShot(KeyAlgorithms keyAlgorithm,
                                       KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                       ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                                       String staticProvider,
                                       String ephemeralProvider) throws Exception {
        KeyPair keyPair = generateKeyPair(staticProvider, keyAlgorithm);
        
        // Encrypt key
        EncryptionCore.AsymmetricEncryptionResult result =
                                    EncryptionCore.encryptKey(true,
                                                              keyPair.getPublic(),
                                                              keyEncryptionAlgorithm,
                                                              contentEncryptionAlgorithm);
        // Decrypt key
        assertTrue("enc", Arrays.equals(result.getContentEncryptionKey(),
                                    EncryptionCore.decryptKey(true,
                                                              keyPair.getPrivate(), 
                                                              result.getEncryptedKey(), 
                                                              result.getEphemeralKey(), 
                                                              keyEncryptionAlgorithm, 
                                                              contentEncryptionAlgorithm)));
        // Encrypt key
        result = 
                                    EncryptionCore.encryptKey(false,
                                                              keyPair.getPublic(),
                                                              keyEncryptionAlgorithm,
                                                              contentEncryptionAlgorithm);
        // Decrypt key
        assertTrue("enc2", Arrays.equals(result.getContentEncryptionKey(),
                                    EncryptionCore.decryptKey(false,
                                                              keyPair.getPrivate(), 
                                                              result.getEncryptedKey(), 
                                                              result.getEphemeralKey(), 
                                                              keyEncryptionAlgorithm, 
                                                              contentEncryptionAlgorithm)));
        // Decrypt key
        assertTrue("enc3" + keyEncryptionAlgorithm, Arrays.equals(result.getContentEncryptionKey(),
                                    EncryptionCore.decryptKey(true,
                                                              keyPair.getPrivate(), 
                                                              result.getEncryptedKey(), 
                                                              result.getEphemeralKey(), 
                                                              keyEncryptionAlgorithm, 
                                                              contentEncryptionAlgorithm))
                            || !keyEncryptionAlgorithm.isRsa());
 
        EncryptionCore.setEcProvider(staticProvider, ephemeralProvider);

    }
    
    private void asymEncryptionProviderShot(KeyAlgorithms keyAlgorithm,
                                            KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                            ContentEncryptionAlgorithms contentEncryptionAlgorithm) throws Exception {
        asymEncryptionOneShot(keyAlgorithm, 
                              keyEncryptionAlgorithm, 
                              contentEncryptionAlgorithm, 
                              null,
                              null);

        asymEncryptionOneShot(keyAlgorithm, 
                              keyEncryptionAlgorithm, 
                              contentEncryptionAlgorithm,
                              null,
                              ALT_PROVIDER);

        asymEncryptionOneShot(keyAlgorithm,
                              keyEncryptionAlgorithm,
                              contentEncryptionAlgorithm,
                              ALT_PROVIDER,
                              null);
        
        asymEncryptionOneShot(keyAlgorithm,
                              keyEncryptionAlgorithm,
                              contentEncryptionAlgorithm,
                              ALT_PROVIDER,
                              ALT_PROVIDER);
    }
    
    @Test
    public void encryptionTest() throws Exception {
        asymEncryptionProviderShot(KeyAlgorithms.P_256,
                                   KeyEncryptionAlgorithms.ECDH_ES,
                                   ContentEncryptionAlgorithms.A256GCM);
        asymEncryptionProviderShot(KeyAlgorithms.X25519,
                                   KeyEncryptionAlgorithms.ECDH_ES,
                                   ContentEncryptionAlgorithms.A256GCM);
        asymEncryptionProviderShot(KeyAlgorithms.X448,
                                   KeyEncryptionAlgorithms.ECDH_ES,
                                   ContentEncryptionAlgorithms.A256GCM);
        asymEncryptionProviderShot(KeyAlgorithms.RSA2048,
                                   KeyEncryptionAlgorithms.RSA_OAEP_256,
                                   ContentEncryptionAlgorithms.A256GCM);
        asymEncryptionProviderShot(KeyAlgorithms.RSA2048,
                                   KeyEncryptionAlgorithms.RSA_OAEP,
                                   ContentEncryptionAlgorithms.A256CBC_HS512);
    }
    
    private void signatureOneShot(KeyAlgorithms keyAlgorithm,
                                  String keyProvider,
                                  String signatureProvider) throws Exception {
        KeyPair keyPair = generateKeyPair(keyProvider, keyAlgorithm);

        byte[] signature = SignatureWrapper.sign(keyPair.getPrivate(),
                                                 keyAlgorithm.getRecommendedSignatureAlgorithm(), 
                                                 DATA_TO_SIGN, 
                                                 signatureProvider);
        
        SignatureWrapper.validate(keyPair.getPublic(), 
                                  keyAlgorithm.getRecommendedSignatureAlgorithm(), 
                                  DATA_TO_SIGN, 
                                  signature, 
                                  signatureProvider);
    }
    
    private void signatureProviderShot(KeyAlgorithms keyAlgorithm) throws Exception {
        signatureOneShot(keyAlgorithm, null,         null);
        signatureOneShot(keyAlgorithm, null,         ALT_PROVIDER);
        signatureOneShot(keyAlgorithm, ALT_PROVIDER, null);
        signatureOneShot(keyAlgorithm, ALT_PROVIDER, ALT_PROVIDER);
    }
    
    @Test
    public void signatureTest() throws Exception {
        signatureProviderShot(KeyAlgorithms.P_256);
        signatureProviderShot(KeyAlgorithms.ED25519);
        signatureProviderShot(KeyAlgorithms.ED448);
        signatureProviderShot(KeyAlgorithms.RSA2048);
    }
    
    void hmacKdfRun(String ikmHex,
                    String saltHex,
                    String infoHex, 
                    int keyLen, 
                    String okmHex) throws Exception {
        assertTrue("KDF",
                   HexaDecimal.encode(
                       EncryptionCore.hmacKdf(HexaDecimal.decode(ikmHex),
                                              HexaDecimal.decode(saltHex),
                                              HexaDecimal.decode(infoHex),
                                              keyLen)).equals(okmHex));
    }
    
    @Test
    public void hmacKdfTest() throws Exception {

        // From appendix A of RFC 5869
        
        // A.1
        hmacKdfRun("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                   "000102030405060708090a0b0c",
                   "f0f1f2f3f4f5f6f7f8f9",
                   42,
                   "3cb25f25faacd57a90434f64d0362f2a" +
                      "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
                      "34007208d5b887185865");

        // A.2
        hmacKdfRun("000102030405060708090a0b0c0d0e0f" +
                     "101112131415161718191a1b1c1d1e1f" +
                     "202122232425262728292a2b2c2d2e2f" +
                     "303132333435363738393a3b3c3d3e3f" +
                     "404142434445464748494a4b4c4d4e4f",
                   "606162636465666768696a6b6c6d6e6f" +
                     "707172737475767778797a7b7c7d7e7f" +
                     "808182838485868788898a8b8c8d8e8f" +
                     "909192939495969798999a9b9c9d9e9f" +
                     "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                   "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
                     "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
                     "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
                     "e0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
                     "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                   82,
                   "b11e398dc80327a1c8e7f78c596a4934" +
                     "4f012eda2d4efad8a050cc4c19afa97c" +
                     "59045a99cac7827271cb41c65e590e09" +
                     "da3275600c2f09b8367793a9aca3db71" +
                     "cc30c58179ec3e87c14c01d5c1f3434f" +
                     "1d87");

        // A.3
        hmacKdfRun("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                   "",
                   "",
                   42,
                   "8da4e775a563c18f715f802a063c5a31" +
                      "b8a11f5c5ee1879ec3454e5f3c738d2d" +
                      "9d201395faa4b61a96c8");       
    }
    
    @Test
    public void concatKdfTest() throws Exception {
        String derivedKey = "pgs50IOZ6BxfqvTSie4t9OjWxGr4whiHo1v9Dti93CRiJE2PP60FojLatVVrcjg3BxpuFjnlQxL97GOwAfcwLA";
        String kdfed = Base64URL.encode(EncryptionCore.concatKdf(
                Base64URL.decode("Sq8rGLm4rEtzScmnSsY5r1n-AqBl_iBU8FxN80Uc0S0"),
                ContentEncryptionAlgorithms.A256CBC_HS512.getJoseAlgorithmId(), 
                64));
        assertTrue("kdf", derivedKey.equals(kdfed));
    }
    
    @Test
    public void pemTest() {
        readAndVerifySeparatePrivPub("openssl-ed25519-priv", "openssl-ed25519-pub", true);
        readAndVerifyKeyPair("openssl-ed25519-priv", false);
        readAndVerifyKeyPair("ed25519-combined-privpub", true);
        readAndVerifyKeyPair("rsa-priv", true);
        readAndVerifyCertificatePath("ed25519-certpath-key", 2);
        readCertificatePath("ed25519-certpath-key", 2);
        readCertificatePath("two-ee-cert", null);
    }

    private void readCertificatePath(String certPath, Integer pathLen) {
        try {
            int l = PEMDecoder.getCertificatePath(readPem(certPath)).length;
            PEMDecoder.getCertificatePath(readPem(certPath));
            assertFalse("cert", pathLen == null);
            assertTrue("pathLen", l == pathLen);
        } catch (Exception e) {
            assertTrue("should not: " + e.getMessage(), pathLen == null);
        }
    }

    private void readAndVerifyCertificatePath(String certPathAndKey, Integer pathLen) {
        String alias = "myKey";
        String password = "fj63dk09hg";
        try {
            KeyStore keyStore = PEMDecoder.getKeyStore(readPem(certPathAndKey), 
                                                       alias, 
                                                       password);
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
            int l = keyStore.getCertificateChain(alias).length;
            assertFalse("priv+cert", pathLen == null);
            assertTrue("pathLen", l == pathLen);
            checkKeys(privateKey, keyStore.getCertificate(alias).getPublicKey());
        } catch (Exception e) {
            assertTrue("should not: " + e.getMessage(), pathLen == null);
        }
    }

    private void readAndVerifySeparatePrivPub(String priv, String pub, boolean ok) {
        try {
            PrivateKey privateKey = getPrivateKey(priv);
            PublicKey publicKey = getPublicKey(pub);
            assertTrue("priv+pub", ok);
            checkKeys(privateKey, publicKey);
        } catch (Exception e) {
            assertFalse("should not: " + e.getMessage(), ok);
        }
    }
    
    private void readAndVerifyKeyPair(String priv, boolean ok) {
        try {
            KeyPair keyPair = getKeyPair(priv);
            assertTrue("keypair", ok);
            checkKeys(keyPair.getPrivate(), keyPair.getPublic());
        } catch (Exception e) {
            assertFalse("should not: " + e.getMessage(), ok);
        }
    }
    
    private void checkKeys(PrivateKey privateKey, PublicKey publicKey) {
        KeyAlgorithms keyAlg = KeyAlgorithms.getKeyAlgorithm(publicKey);
        AsymSignatureAlgorithms sigAlg = keyAlg.getRecommendedSignatureAlgorithm();
        byte[] signature = SignatureWrapper.sign(privateKey, sigAlg, DATA_TO_SIGN, null);
        SignatureWrapper.validate(publicKey, sigAlg, DATA_TO_SIGN, signature, null);
    }

    byte[] readPem(String name) {
        InputStream inputStream = this.getClass().getResourceAsStream(name + ".pem");
        if (inputStream == null) {
            throw new CryptoException("Could not read: " + name + ".pem");
        }
        return IO.getByteArrayFromInputStream(inputStream);
    }

    private PublicKey getPublicKey(String pub) {
        return PEMDecoder.getPublicKey(readPem(pub));
    }

    private PrivateKey getPrivateKey(String priv) {
        return PEMDecoder.getPrivateKey(readPem(priv));
    }

    private KeyPair getKeyPair(String priv) {
        return PEMDecoder.getKeyPair(readPem(priv));
    }
}
