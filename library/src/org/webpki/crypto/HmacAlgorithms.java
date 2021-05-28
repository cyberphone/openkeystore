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

import java.security.GeneralSecurityException;

import javax.crypto.Mac;

import javax.crypto.spec.SecretKeySpec;

/**
 * HMAC algorithms including an implementation.
 *
 */
public enum HmacAlgorithms implements SignatureAlgorithms {

    HMAC_SHA1   ("http://www.w3.org/2000/09/xmldsig#hmac-sha1",
                 null,    0, "HmacSHA1",   HashAlgorithms.SHA1,   false),
    
    HMAC_SHA256 ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
                 "HS256", 5, "HmacSHA256", HashAlgorithms.SHA256, true),

    HMAC_SHA384 ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha384",
                 "HS384", 6, "HmacSHA384", HashAlgorithms.SHA384, true),

    HMAC_SHA512 ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha512",
                 "HS512", 7, "HmacSHA512", HashAlgorithms.SHA512, true);

    private final String sksId;     // As expressed in SKS
    private final String joseId;    // JOSE
    private final int coseId;       // COSE
    private final String jceName;   // As expressed for JCE
    private HashAlgorithms digestAlg; 
    private boolean sksMandatory;   // If required in SKS

    private HmacAlgorithms(String sksId, String joseId, int coseId, String jceName,
                           HashAlgorithms digestAlg, boolean sksMandatory) {
        this.sksId = sksId;
        this.joseId = joseId;
        this.coseId = coseId;
        this.jceName = jceName;
        this.digestAlg = digestAlg;
        this.sksMandatory = sksMandatory;
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

    public byte[] digest(byte[] key, byte[] data) throws IOException, GeneralSecurityException {
        Mac mac = Mac.getInstance(getJceName());
        mac.init(new SecretKeySpec(key, "RAW"));  // Note: any length is OK in HMAC
        return mac.doFinal(data);
    }

    public static boolean testAlgorithmUri(String sksId) {
        for (HmacAlgorithms alg : HmacAlgorithms.values()) {
            if (sksId.equals(alg.sksId)) {
                return true;
            }
        }
        return false;
    }

    public static HmacAlgorithms getAlgorithmFromId(String algorithmId,
                                                    AlgorithmPreferences algorithmPreferences) {
        for (HmacAlgorithms alg : values()) {
            if (algorithmId.equals(alg.sksId)) {
                if (algorithmPreferences == AlgorithmPreferences.JOSE) {
                    throw new IllegalArgumentException("JOSE algorithm expected: " + algorithmId);
                }
                return alg;
            }
            if (algorithmId.equals(alg.joseId)) {
                if (algorithmPreferences == AlgorithmPreferences.SKS) {
                    throw new IllegalArgumentException("SKS algorithm expected: " + algorithmId);
                }
                return alg;
            }
        }
        throw new IllegalArgumentException("Unknown HMAC algorithm: " + algorithmId);
    }

    @Override
    public String getAlgorithmId(AlgorithmPreferences algorithmPreferences) {
        if (joseId == null) {
            if (algorithmPreferences == AlgorithmPreferences.JOSE) {
                throw new IllegalArgumentException("There is no JOSE algorithm for: " + 
                                                   this.toString());
            }
            return sksId;
        }
        return algorithmPreferences == AlgorithmPreferences.SKS ? sksId : joseId;
    }

    @Override
    public boolean isDeprecated() {
        return this == HMAC_SHA1;
    }

    @Override
    public HashAlgorithms getDigestAlgorithm() {
        return digestAlg;
    }

    @Override
    public KeyTypes getKeyType() {
        return KeyTypes.SYM;
    }

    @Override
    public int getCoseAlgorithmId() {
        if (coseId == 0) {
            throw new IllegalArgumentException("There is no COSE HMAC algorithm for :" + 
                                               this.toString());
        }
        return coseId;
    }

    public static HmacAlgorithms getAlgorithmFromId(int coseAlgorithmId) {
        for (HmacAlgorithms alg : HmacAlgorithms.values()) {
            if (coseAlgorithmId == alg.coseId) {
                alg.getCoseAlgorithmId();
                return alg;
            }
        }
        throw new IllegalArgumentException("Unknown COSE HMAC algorithm: " +
                                           coseAlgorithmId);
    }
}
