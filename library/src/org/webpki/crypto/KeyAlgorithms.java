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
package org.webpki.crypto;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;

import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Asymmetric key algorithms
 */
public enum KeyAlgorithms implements CryptoAlgorithms {

    RSA1024    ("https://webpki.github.io/sks/algorithm#rsa1024", 
                null,
                "RSA",
                1024,
                AsymSignatureAlgorithms.RSA_SHA256,
                false,
                false,
                true,
                null,
                null),
    
    RSA2048    ("https://webpki.github.io/sks/algorithm#rsa2048", 
                null,
                "RSA",
                2048,
                AsymSignatureAlgorithms.RSA_SHA256,
                false,
                true,
                false,
                null,
                null),
    
    RSA3072    ("https://webpki.github.io/sks/algorithm#rsa3072", 
                null,
                "RSA",
                3072,
                AsymSignatureAlgorithms.RSA_SHA512,
                false,
                false,
                false,
                null,
                null),
    
    RSA4096    ("https://webpki.github.io/sks/algorithm#rsa4096", 
                null,
                "RSA",
                4096,
                AsymSignatureAlgorithms.RSA_SHA512,
                false,
                false,
                false,
                null,
                null),
    
    RSA1024_EXP ("https://webpki.github.io/sks/algorithm#rsa1024.exp",
                null,
                "RSA",
                1024,
                AsymSignatureAlgorithms.RSA_SHA256,
                true,
                false,
                true,
                null,
                null),
    
    RSA2048_EXP ("https://webpki.github.io/sks/algorithm#rsa2048.exp", 
                null,
                "RSA",
                2048,
                AsymSignatureAlgorithms.RSA_SHA256,
                true,
                false,
                false,
                null,
                null),
    
    RSA3072_EXP ("https://webpki.github.io/sks/algorithm#rsa3072.exp", 
                null,
                "RSA",
                3072,
                AsymSignatureAlgorithms.RSA_SHA512,
                true,
                false,
                false,
                null,
                null),
    
    RSA4096_EXP ("https://webpki.github.io/sks/algorithm#rsa4096.exp",
                null,
                "RSA",
                4096,
                AsymSignatureAlgorithms.RSA_SHA512,
                true,
                false,
                false,
                null,
                null),
    
    NIST_P_256 ("https://webpki.github.io/sks/algorithm#ec.nist.p256",
                "P-256",
                "secp256r1",
                256,
                AsymSignatureAlgorithms.ECDSA_SHA256,
                false,
                true,
                false,
                "1.2.840.10045.3.1.7",
                new byte[]
                   {(byte)0x30, (byte)0x59, (byte)0x30, (byte)0x13, (byte)0x06, (byte)0x07, (byte)0x2A, (byte)0x86,
                    (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x02, (byte)0x01, (byte)0x06, (byte)0x08, (byte)0x2A,
                    (byte)0x86, (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x03, (byte)0x01, (byte)0x07, (byte)0x03,
                    (byte)0x42, (byte)0x00, (byte)0x04, (byte)0x8B, (byte)0xDF, (byte)0x5D, (byte)0xA2, (byte)0xBE,
                    (byte)0x57, (byte)0x73, (byte)0xAC, (byte)0x78, (byte)0x86, (byte)0xD3, (byte)0xE5, (byte)0xE6,
                    (byte)0xC4, (byte)0xA5, (byte)0x6C, (byte)0x32, (byte)0xE2, (byte)0x28, (byte)0xBE, (byte)0xA0,
                    (byte)0x0F, (byte)0x8F, (byte)0xBF, (byte)0x29, (byte)0x1E, (byte)0xC6, (byte)0x67, (byte)0xB3,
                    (byte)0x51, (byte)0x99, (byte)0xB7, (byte)0xAD, (byte)0x13, (byte)0x0C, (byte)0x5A, (byte)0x7C,
                    (byte)0x66, (byte)0x4B, (byte)0x47, (byte)0xF6, (byte)0x1F, (byte)0x41, (byte)0xE9, (byte)0xB3,
                    (byte)0xB2, (byte)0x40, (byte)0xC0, (byte)0x65, (byte)0xF8, (byte)0x8F, (byte)0x30, (byte)0x0A,
                    (byte)0xCA, (byte)0x5F, (byte)0xB5, (byte)0x09, (byte)0x6E, (byte)0x95, (byte)0xCF, (byte)0x78,
                    (byte)0x7C, (byte)0x0D, (byte)0xB2}),
    
    NIST_P_384 ("https://webpki.github.io/sks/algorithm#ec.nist.p384",
                "P-384",
                "secp384r1",
                384,
                AsymSignatureAlgorithms.ECDSA_SHA384,
                false,
                true,
                false,
                "1.3.132.0.34",
                new byte[]
                   {(byte)0x30, (byte)0x76, (byte)0x30, (byte)0x10, (byte)0x06, (byte)0x07, (byte)0x2A, (byte)0x86,
                    (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x02, (byte)0x01, (byte)0x06, (byte)0x05, (byte)0x2B,
                    (byte)0x81, (byte)0x04, (byte)0x00, (byte)0x22, (byte)0x03, (byte)0x62, (byte)0x00, (byte)0x04,
                    (byte)0x63, (byte)0x5C, (byte)0x35, (byte)0x5C, (byte)0xC0, (byte)0xDF, (byte)0x90, (byte)0x16,
                    (byte)0xA6, (byte)0x18, (byte)0xF1, (byte)0x50, (byte)0xA7, (byte)0x73, (byte)0xE7, (byte)0x05,
                    (byte)0x22, (byte)0x36, (byte)0xF7, (byte)0xDC, (byte)0x9F, (byte)0xD8, (byte)0xA5, (byte)0xAC,
                    (byte)0x71, (byte)0x9F, (byte)0x1C, (byte)0x9A, (byte)0x71, (byte)0x94, (byte)0x8B, (byte)0x81,
                    (byte)0x15, (byte)0x32, (byte)0x24, (byte)0x92, (byte)0x11, (byte)0x11, (byte)0xDC, (byte)0x7E,
                    (byte)0x9D, (byte)0x70, (byte)0x1A, (byte)0x9B, (byte)0x83, (byte)0x33, (byte)0x8B, (byte)0x59,
                    (byte)0xC1, (byte)0x93, (byte)0x34, (byte)0x7F, (byte)0x58, (byte)0x0D, (byte)0x91, (byte)0xC4,
                    (byte)0xD2, (byte)0x20, (byte)0x8F, (byte)0x64, (byte)0x16, (byte)0x16, (byte)0xEE, (byte)0x07,
                    (byte)0x51, (byte)0xC3, (byte)0xF8, (byte)0x56, (byte)0x5B, (byte)0xCD, (byte)0x49, (byte)0xFE,
                    (byte)0xE0, (byte)0xE2, (byte)0xD5, (byte)0xC5, (byte)0x79, (byte)0xD1, (byte)0xA6, (byte)0x18,
                    (byte)0x82, (byte)0xBD, (byte)0x65, (byte)0x83, (byte)0xB6, (byte)0x84, (byte)0x77, (byte)0xE8,
                    (byte)0x1F, (byte)0xB8, (byte)0xD7, (byte)0x3D, (byte)0x79, (byte)0x88, (byte)0x2E, (byte)0x98}),
    
    NIST_P_521  ("https://webpki.github.io/sks/algorithm#ec.nist.p521",
                "P-521",
                "secp521r1",
                521,
                AsymSignatureAlgorithms.ECDSA_SHA512,
                false,
                true,
                false,
                "1.3.132.0.35",
                new byte[]
                   {(byte)0x30, (byte)0x81, (byte)0x9B, (byte)0x30, (byte)0x10, (byte)0x06, (byte)0x07, (byte)0x2A,
                    (byte)0x86, (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x02, (byte)0x01, (byte)0x06, (byte)0x05,
                    (byte)0x2B, (byte)0x81, (byte)0x04, (byte)0x00, (byte)0x23, (byte)0x03, (byte)0x81, (byte)0x86,
                    (byte)0x00, (byte)0x04, (byte)0x01, (byte)0xFC, (byte)0xA0, (byte)0x56, (byte)0x27, (byte)0xB7,
                    (byte)0x68, (byte)0x25, (byte)0xC5, (byte)0x83, (byte)0xD1, (byte)0x34, (byte)0x0A, (byte)0xAE,
                    (byte)0x96, (byte)0x1D, (byte)0xDC, (byte)0xE0, (byte)0x95, (byte)0xC5, (byte)0xE0, (byte)0x25,
                    (byte)0x1F, (byte)0x46, (byte)0xF6, (byte)0x36, (byte)0xD7, (byte)0x3F, (byte)0xD9, (byte)0x5A,
                    (byte)0x15, (byte)0xE3, (byte)0x05, (byte)0xBA, (byte)0x14, (byte)0x06, (byte)0x1B, (byte)0xEB,
                    (byte)0xD4, (byte)0x88, (byte)0xFC, (byte)0x0D, (byte)0x87, (byte)0x02, (byte)0x15, (byte)0x4E,
                    (byte)0x7E, (byte)0xC0, (byte)0x9F, (byte)0xF6, (byte)0x1C, (byte)0x80, (byte)0x2C, (byte)0xE6,
                    (byte)0x0D, (byte)0xF5, (byte)0x0E, (byte)0x6C, (byte)0xD9, (byte)0x55, (byte)0xFA, (byte)0xBD,
                    (byte)0x6B, (byte)0x55, (byte)0xA1, (byte)0x0E, (byte)0x00, (byte)0x55, (byte)0x12, (byte)0x35,
                    (byte)0x8D, (byte)0xFC, (byte)0x0A, (byte)0x42, (byte)0xE5, (byte)0x78, (byte)0x09, (byte)0xD6,
                    (byte)0xF6, (byte)0x0C, (byte)0xBE, (byte)0x15, (byte)0x0A, (byte)0x7D, (byte)0xC2, (byte)0x2E,
                    (byte)0x98, (byte)0xA1, (byte)0xE1, (byte)0x6A, (byte)0xF1, (byte)0x1F, (byte)0xD2, (byte)0x9F,
                    (byte)0x9A, (byte)0x81, (byte)0x65, (byte)0x51, (byte)0x8F, (byte)0x6E, (byte)0xF1, (byte)0x3B,
                    (byte)0x95, (byte)0x6B, (byte)0xCE, (byte)0x51, (byte)0x09, (byte)0xFF, (byte)0x23, (byte)0xDC,
                    (byte)0xE8, (byte)0x71, (byte)0x1A, (byte)0x94, (byte)0xC7, (byte)0x8E, (byte)0x4A, (byte)0xA9,
                    (byte)0x22, (byte)0xA8, (byte)0x87, (byte)0x64, (byte)0xD0, (byte)0x36, (byte)0xAF, (byte)0xD3,
                    (byte)0x69, (byte)0xAC, (byte)0xCA, (byte)0xCB, (byte)0x1A, (byte)0x96}),
                    
    SECG_K_256 ("https://webpki.github.io/sks/algorithm#ec.secg.p256k1", 
                null,
                "secp256k1",
                256,
                AsymSignatureAlgorithms.ECDSA_SHA256,
                false,
                false,
                true,
                "1.3.132.0.10",
                new byte[]
                   {(byte)0x30, (byte)0x56, (byte)0x30, (byte)0x10, (byte)0x06, (byte)0x07, (byte)0x2A, (byte)0x86,
                    (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x02, (byte)0x01, (byte)0x06, (byte)0x05, (byte)0x2B,
                    (byte)0x81, (byte)0x04, (byte)0x00, (byte)0x0A, (byte)0x03, (byte)0x42, (byte)0x00, (byte)0x04,
                    (byte)0xA9, (byte)0xF7, (byte)0xEF, (byte)0x65, (byte)0x26, (byte)0x2F, (byte)0xDB, (byte)0x11,
                    (byte)0xE3, (byte)0xDA, (byte)0x7C, (byte)0x9D, (byte)0xDF, (byte)0x1F, (byte)0x2E, (byte)0x32,
                    (byte)0x49, (byte)0x99, (byte)0x4B, (byte)0x02, (byte)0x07, (byte)0x02, (byte)0x78, (byte)0x94,
                    (byte)0xFF, (byte)0x1C, (byte)0x5A, (byte)0x30, (byte)0xB3, (byte)0x39, (byte)0x44, (byte)0xF4,
                    (byte)0x50, (byte)0xBE, (byte)0xC9, (byte)0x6C, (byte)0xAE, (byte)0xE6, (byte)0xA5, (byte)0xC0,
                    (byte)0x8B, (byte)0xF9, (byte)0x29, (byte)0x5B, (byte)0xA0, (byte)0x16, (byte)0xC5, (byte)0x36,
                    (byte)0xDD, (byte)0xE6, (byte)0xA1, (byte)0x21, (byte)0x6D, (byte)0x80, (byte)0x77, (byte)0xD7,
                    (byte)0x5B, (byte)0xC1, (byte)0x32, (byte)0x44, (byte)0xA6, (byte)0x32, (byte)0x06, (byte)0xA9}),                       
    
    BRAINPOOL_P_256 (
                "https://webpki.github.io/sks/algorithm#ec.brainpool.p256r1",
                null,
                "brainpoolP256r1",
                256,
                AsymSignatureAlgorithms.ECDSA_SHA256,
                false,
                false,
                true,
                "1.3.36.3.3.2.8.1.1.7",
                new byte[]
                   {(byte)0x30, (byte)0x5A, (byte)0x30, (byte)0x14, (byte)0x06, (byte)0x07, (byte)0x2A, (byte)0x86,
                    (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x02, (byte)0x01, (byte)0x06, (byte)0x09, (byte)0x2B,
                    (byte)0x24, (byte)0x03, (byte)0x03, (byte)0x02, (byte)0x08, (byte)0x01, (byte)0x01, (byte)0x07,
                    (byte)0x03, (byte)0x42, (byte)0x00, (byte)0x04, (byte)0x26, (byte)0x3C, (byte)0x91, (byte)0x3F,
                    (byte)0x6B, (byte)0x91, (byte)0x10, (byte)0x6F, (byte)0xE4, (byte)0xA2, (byte)0x2D, (byte)0xA4,
                    (byte)0xBB, (byte)0xAB, (byte)0xCE, (byte)0x9E, (byte)0x41, (byte)0x01, (byte)0x0B, (byte)0xB0,
                    (byte)0xC3, (byte)0x84, (byte)0xEF, (byte)0x35, (byte)0x0D, (byte)0x66, (byte)0xEE, (byte)0x0C,
                    (byte)0xEC, (byte)0x60, (byte)0xB6, (byte)0xF5, (byte)0x54, (byte)0x54, (byte)0x27, (byte)0x2A,
                    (byte)0x1D, (byte)0x07, (byte)0x61, (byte)0xB0, (byte)0xC3, (byte)0x01, (byte)0xE8, (byte)0xCB,
                    (byte)0x52, (byte)0xF5, (byte)0x03, (byte)0xC1, (byte)0x0C, (byte)0x3F, (byte)0xF0, (byte)0x97,
                    (byte)0xCD, (byte)0xC9, (byte)0x45, (byte)0xF3, (byte)0x21, (byte)0xC5, (byte)0xCF, (byte)0x41,
                    (byte)0x17, (byte)0xF3, (byte)0x3A, (byte)0xB4}),

    ED25519    ("https://webpki.github.io/sks/algorithm#ed25519", 
                "Ed25519",
                "Ed25519",
                256,
                AsymSignatureAlgorithms.ED25519,
                false,
                false,
                false,
                "1.3.101.112",
                null),

    ED448      ("https://webpki.github.io/sks/algorithm#ed448", 
                "Ed448",
                "Ed448",
                448,
                AsymSignatureAlgorithms.ED448,
                false,
                false,
                false,
                "1.3.101.113",
                null),

    X25519     ("https://webpki.github.io/sks/algorithm#x25519",
                "X25519",
                "X25519",
                256,
                null,
                false,
                false,
                false,
                "1.3.101.110",
                null),

    X448       ("https://webpki.github.io/sks/algorithm#x448",
                "X448",
                "X448",
                448,
                null,
                false,
                false,
                false,
                "1.3.101.111",
                null);

    private final String sksName;                    // As expressed in SKS
    private final String joseName;                   // As expressed in JOSE.  Only applicable EC curves
    private final String jceName;                    // As expressed for JCE
    private final int lengthInBits;                  // You guessed it :-)
    private final AsymSignatureAlgorithms prefAlg;   // A sort of a "guide"
    private final boolean hasParameters;             // Parameter value required?
    private final boolean sksMandatory;              // If required in SKS
    private final boolean deprecated;                // Oracle thinks so for certain EC curves
    private final String ecDomainOid;                // EC domain as expressed in ASN.1 messages, null for RSA
    private final ECParameterSpec ecParmSpec;        // EC for creating a BC/JDK compatible method
    private final boolean rsa;                       // RSA algorithm
    private final boolean ecdsa;                     // EC/ECDSA algorithm

    public static final String XML_DSIG_CURVE_PREFIX = "urn:oid:";

    private KeyAlgorithms(String sksName,
                          String joseName,
                          String jceName,
                          int lengthInBits,
                          AsymSignatureAlgorithms prefAlg,
                          boolean hasParameters,
                          boolean sksMandatory,
                          boolean deprecated,
                          String ecDomainOid,
                          byte[] samplePublicKey) {
        this.sksName = sksName;
        this.joseName = joseName;
        this.jceName = jceName;
        this.lengthInBits = lengthInBits;
        this.prefAlg = prefAlg;
        this.hasParameters = hasParameters;
        this.sksMandatory = sksMandatory;
        this.deprecated = deprecated;
        this.ecDomainOid = ecDomainOid;
        // JDK does not offer a public method for creating EC public keys from
        // algorithm names + data.  This is a workaround that fortunately works 
        // with JDK, BC, and Android.
        ECParameterSpec tempEcParmSpec = null;
        if (samplePublicKey != null) {
            try {
                tempEcParmSpec = ((ECPublicKey) KeyFactory.getInstance("EC").generatePublic(
                        new X509EncodedKeySpec(samplePublicKey))).getParams();
            } catch (Exception e) {
                if (!deprecated) {
                    new RuntimeException(e);
                }
            }
        }
        this.ecParmSpec = tempEcParmSpec;
        this.rsa = jceName.equals("RSA");
        this.ecdsa = tempEcParmSpec != null;
    }


    @Override
    public boolean isSymmetric() {
        return false;
    }

    @Override
    public boolean isMandatorySksAlgorithm() {
        return sksMandatory;
    }

    @Override
    public String getJceName() {
        return jceName;
    }

    @Override
    public String getOid() {
        return null;
    }

    public String getECDomainOID() {
        return ecDomainOid;
    }

    @Override
    public boolean isEcdsa() {
        return ecdsa;
    }

    @Override
    public boolean isRsa() {
        return rsa;
    }

    @Override
    public boolean isOkp() {
        return !(ecdsa || rsa);
    }

    public int getPublicKeySizeInBits() {
        return lengthInBits;
    }

    public AsymSignatureAlgorithms getRecommendedSignatureAlgorithm() {
        return prefAlg;
    }

    public boolean hasParameters() {
        return hasParameters;
    }

    public ECParameterSpec getECParameterSpec() {
        return ecParmSpec;
    }

    public static KeyAlgorithms getECKeyAlgorithm(ECParameterSpec actual) throws IOException {
        for (KeyAlgorithms alg : values()) {
            if (alg.isEcdsa()) {
                ECParameterSpec ref = alg.ecParmSpec;
                if (ref.getCofactor() == actual.getCofactor() &&
                    ref.getOrder().equals(actual.getOrder()) &&
                    ref.getCurve().equals(actual.getCurve()) &&
                    ref.getGenerator().equals(actual.getGenerator())) {
                    return alg;
                }
            }
        }
        throw new IOException("Unknown EC type: " + actual.toString());
    }

    public static KeyAlgorithms getKeyAlgorithm(PublicKey publicKey, Boolean keyParameters) throws IOException {
        if (publicKey instanceof ECKey) {
            return getECKeyAlgorithm(((ECPublicKey) publicKey).getParams());
        }
        if (publicKey instanceof RSAKey) {
            byte[] modblob = ((RSAPublicKey) publicKey).getModulus().toByteArray();
            int lengthInBits = (modblob[0] == 0 ? modblob.length - 1 : modblob.length) * 8;
            for (KeyAlgorithms alg : values()) {
                if (alg.ecDomainOid == null && lengthInBits == alg.lengthInBits &&
                        (keyParameters == null || alg.hasParameters == keyParameters)) {
                    return alg;
                }
            }
            throw new IOException("Unsupported RSA key size: " + lengthInBits);
        }
        return OkpSupport.getOkpKeyAlgorithm(publicKey);
    }

    // Public keys read from specific security providers are not comparable to 
    // public keys created directly from crypto parameters and thus don't compare :-(
    // This method normalizes the former.
    public static PublicKey normalizePublicKey(PublicKey publicKey) throws GeneralSecurityException, IOException {
        if (publicKey instanceof ECKey) {
            return KeyFactory.getInstance("EC")
                    .generatePublic(new ECPublicKeySpec(((ECPublicKey)publicKey).getW(),
                                                        ((ECPublicKey)publicKey).getParams()));
        }
        if (publicKey instanceof RSAKey) {
            return KeyFactory.getInstance("RSA").generatePublic(
                    new RSAPublicKeySpec(((RSAPublicKey)publicKey).getModulus(),
                                         ((RSAPublicKey)publicKey).getPublicExponent()));
        }
        KeyAlgorithms keyAlgorithm = OkpSupport.getOkpKeyAlgorithm(publicKey);
        return OkpSupport.raw2PublicOkpKey(OkpSupport.public2RawOkpKey(publicKey, keyAlgorithm),
                                           keyAlgorithm);
    }

    public static KeyAlgorithms getKeyAlgorithm(PublicKey publicKey) throws IOException {
        return getKeyAlgorithm(publicKey, null);
    }

    public static KeyAlgorithms getKeyAlgorithmFromId(String algorithmId, 
                                                      AlgorithmPreferences algorithmPreferences) throws IOException {
        for (KeyAlgorithms alg : values()) {
            if (algorithmId.equals(alg.sksName)) {
                if (algorithmPreferences == AlgorithmPreferences.JOSE) {
                    throw new IOException("JOSE algorithm expected: " + algorithmId);
                }
                return alg;
            }
            if (algorithmId.equals(alg.joseName)) {
                if (algorithmPreferences == AlgorithmPreferences.SKS) {
                    throw new IOException("SKS algorithm expected: " + algorithmId);
                }
                return alg;
            }
        }
        throw new IOException("Unknown algorithm: " + algorithmId);
    }

    @Override
    public String getAlgorithmId(AlgorithmPreferences algorithmPreferences) throws IOException {
        if (joseName == null) {
            if (algorithmPreferences == AlgorithmPreferences.JOSE) {
                throw new IOException("There is no JOSE algorithm for: " + toString());
            }
            return sksName;
        }
        return algorithmPreferences == AlgorithmPreferences.SKS ? sksName : joseName;
    }

    @Override
    public boolean isDeprecated() {
        return deprecated;
    }
}
