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

import java.io.IOException;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;

import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * Asymmetric key algorithms.
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
                KeyTypes.RSA),
    
    RSA2048    ("https://webpki.github.io/sks/algorithm#rsa2048", 
                null,
                "RSA",
                2048,
                AsymSignatureAlgorithms.RSA_SHA256,
                false,
                true,
                false,
                null,
                KeyTypes.RSA),
    
    RSA3072    ("https://webpki.github.io/sks/algorithm#rsa3072", 
                null,
                "RSA",
                3072,
                AsymSignatureAlgorithms.RSA_SHA512,
                false,
                false,
                false,
                null,
                KeyTypes.RSA),
    
    RSA4096    ("https://webpki.github.io/sks/algorithm#rsa4096", 
                null,
                "RSA",
                4096,
                AsymSignatureAlgorithms.RSA_SHA512,
                false,
                false,
                false,
                null,
                KeyTypes.RSA),
    
    RSA1024_EXP ("https://webpki.github.io/sks/algorithm#rsa1024.exp",
                null,
                "RSA",
                1024,
                AsymSignatureAlgorithms.RSA_SHA256,
                true,
                false,
                true,
                null,
                KeyTypes.RSA),
    
    RSA2048_EXP ("https://webpki.github.io/sks/algorithm#rsa2048.exp", 
                null,
                "RSA",
                2048,
                AsymSignatureAlgorithms.RSA_SHA256,
                true,
                false,
                false,
                null,
                KeyTypes.RSA),
    
    RSA3072_EXP ("https://webpki.github.io/sks/algorithm#rsa3072.exp", 
                null,
                "RSA",
                3072,
                AsymSignatureAlgorithms.RSA_SHA512,
                true,
                false,
                false,
                null,
                KeyTypes.RSA),
    
    RSA4096_EXP ("https://webpki.github.io/sks/algorithm#rsa4096.exp",
                null,
                "RSA",
                4096,
                AsymSignatureAlgorithms.RSA_SHA512,
                true,
                false,
                false,
                null,
                KeyTypes.RSA),
    
         P_256 ("https://webpki.github.io/sks/algorithm#ec.nist.p256",
                "P-256",
                "secp256r1",
                256,
                AsymSignatureAlgorithms.ECDSA_SHA256,
                false,
                true,
                false,
                "1.2.840.10045.3.1.7",
                KeyTypes.EC),
    
         P_384 ("https://webpki.github.io/sks/algorithm#ec.nist.p384",
                "P-384",
                "secp384r1",
                384,
                AsymSignatureAlgorithms.ECDSA_SHA384,
                false,
                true,
                false,
                "1.3.132.0.34",
                KeyTypes.EC),
    
        P_521  ("https://webpki.github.io/sks/algorithm#ec.nist.p521",
                "P-521",
                "secp521r1",
                521,
                AsymSignatureAlgorithms.ECDSA_SHA512,
                false,
                true,
                false,
                "1.3.132.0.35",
                KeyTypes.EC),
                    
    SECG_K_256 ("https://webpki.github.io/sks/algorithm#ec.secg.p256k1", 
                null,
                "secp256k1",
                256,
                AsymSignatureAlgorithms.ECDSA_SHA256,
                false,
                false,
                true,
                "1.3.132.0.10",
                KeyTypes.EC),                       
    
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
                KeyTypes.EC),

    ED25519    ("https://webpki.github.io/sks/algorithm#ed25519", 
                "Ed25519",
                "Ed25519",
                256,
                AsymSignatureAlgorithms.ED25519,
                false,
                false,
                false,
                "1.3.101.112",
                KeyTypes.EDDSA),

    ED448      ("https://webpki.github.io/sks/algorithm#ed448", 
                "Ed448",
                "Ed448",
                448,
                AsymSignatureAlgorithms.ED448,
                false,
                false,
                false,
                "1.3.101.113",
                KeyTypes.EDDSA),

    X25519     ("https://webpki.github.io/sks/algorithm#x25519",
                "X25519",
                "X25519",
                256,
                null,
                false,
                false,
                false,
                "1.3.101.110",
                KeyTypes.XEC),

    X448       ("https://webpki.github.io/sks/algorithm#x448",
                "X448",
                "X448",
                448,
                null,
                false,
                false,
                false,
                "1.3.101.111",
                KeyTypes.XEC);

    private final String sksName;                    // As expressed in SKS
    private final String joseName;                   // As expressed in JOSE.  Only applicable for EC curves
    private final String jceName;                    // As expressed for JCE
    private final int lengthInBits;                  // You guessed it :-)
    private final AsymSignatureAlgorithms prefAlg;   // A sort of a "guide"
    private final boolean hasParameters;             // Parameter value required?
    private final boolean sksMandatory;              // If required in SKS
    private final boolean deprecated;                // Oracle thinks so for certain EC curves
    private final String ecDomainOid;                // EC domain as expressed in ASN.1 messages, null for RSA
    private final KeyTypes keyType;                  // Core
    private final ECParameterSpec ecParmSpec;        // EC for creating a BC/JDK compatible method

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
                          KeyTypes keyType) {
        this.sksName = sksName;
        this.joseName = joseName;
        this.jceName = jceName;
        this.lengthInBits = lengthInBits;
        this.prefAlg = prefAlg;
        this.hasParameters = hasParameters;
        this.sksMandatory = sksMandatory;
        this.deprecated = deprecated;
        this.ecDomainOid = ecDomainOid;
        this.keyType = keyType;
        ECParameterSpec tempEcParmSpec = null;
        if (keyType == KeyTypes.EC) {
            try {
                AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
                parameters.init(new ECGenParameterSpec(jceName));
                tempEcParmSpec = parameters.getParameterSpec(ECParameterSpec.class);
            } catch (Exception e) {
                if (!deprecated) {
                    new RuntimeException(e);
                }
            }
        }
        this.ecParmSpec = tempEcParmSpec;
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

    public static KeyAlgorithms getECKeyAlgorithm(ECParameterSpec actual) {
        for (KeyAlgorithms alg : values()) {
            if (alg.keyType == KeyTypes.EC) {
                ECParameterSpec ref = alg.ecParmSpec;
                if (ref.getCofactor() == actual.getCofactor() &&
                    ref.getOrder().equals(actual.getOrder()) &&
                    ref.getCurve().equals(actual.getCurve()) &&
                    ref.getGenerator().equals(actual.getGenerator())) {
                    return alg;
                }
            }
        }
        throw new IllegalArgumentException("Unknown EC type: " + actual.toString());
    }

    public static KeyAlgorithms getKeyAlgorithm(Key key, Boolean keyParameters) {
        if (key instanceof ECKey) {
            return getECKeyAlgorithm(((ECKey) key).getParams());
        }
        if (key instanceof RSAKey) {
            byte[] modblob = ((RSAKey) key).getModulus().toByteArray();
            int lengthInBits = (modblob[0] == 0 ? modblob.length - 1 : modblob.length) * 8;
            for (KeyAlgorithms alg : values()) {
                if (alg.ecDomainOid == null && lengthInBits == alg.lengthInBits &&
                        (keyParameters == null || alg.hasParameters == keyParameters)) {
                    return alg;
                }
            }
            throw new IllegalArgumentException("Unsupported RSA key size: " + lengthInBits);
        }
        return OkpSupport.getKeyAlgorithm(key);
    }

    // Public keys read from specific security providers are not comparable to 
    // public keys created directly from crypto parameters and thus don't compare :-(
    // This method normalizes the former.
    public static PublicKey normalizePublicKey(PublicKey publicKey)
            throws GeneralSecurityException, IOException {
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
        KeyAlgorithms keyAlgorithm = OkpSupport.getKeyAlgorithm(publicKey);
        return OkpSupport.raw2PublicKey(OkpSupport.public2RawKey(publicKey, keyAlgorithm),
                                        keyAlgorithm);
    }

    public static KeyAlgorithms getKeyAlgorithm(Key key) {
        return getKeyAlgorithm(key, null);
    }

    public static KeyAlgorithms getKeyAlgorithmFromId(String algorithmId, 
                                                      AlgorithmPreferences algorithmPreferences) {
        for (KeyAlgorithms alg : values()) {
            if (algorithmId.equals(alg.sksName)) {
                if (algorithmPreferences == AlgorithmPreferences.JOSE) {
                    throw new IllegalArgumentException("JOSE algorithm expected: " + algorithmId);
                }
                return alg;
            }
            if (algorithmId.equals(alg.joseName)) {
                if (algorithmPreferences == AlgorithmPreferences.SKS) {
                    throw new IllegalArgumentException("SKS algorithm expected: " + algorithmId);
                }
                return alg;
            }
        }
        throw new IllegalArgumentException("Unknown algorithm: " + algorithmId);
    }

    @Override
    public String getAlgorithmId(AlgorithmPreferences algorithmPreferences) {
        if (joseName == null) {
            if (algorithmPreferences == AlgorithmPreferences.JOSE) {
                throw new IllegalArgumentException("There is no JOSE algorithm for: " + 
                                                   this.toString());
            }
            return sksName;
        }
        return algorithmPreferences == AlgorithmPreferences.SKS ? sksName : joseName;
    }

    @Override
    public boolean isDeprecated() {
        return deprecated;
    }


    @Override
    public KeyTypes getKeyType() {
        return keyType;
    }
}
