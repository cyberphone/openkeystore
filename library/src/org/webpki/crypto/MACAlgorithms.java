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

import javax.crypto.Mac;

import javax.crypto.spec.SecretKeySpec;

public enum MACAlgorithms implements SignatureAlgorithms {

    HMAC_SHA1   ("http://www.w3.org/2000/09/xmldsig#hmac-sha1",
                 null,    "HmacSHA1",   HashAlgorithms.SHA1,   true),
    HMAC_SHA256 ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", 
                 "HS256", "HmacSHA256", HashAlgorithms.SHA256, true),
    HMAC_SHA384 ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha384", 
                 "HS384", "HmacSHA384", HashAlgorithms.SHA384, true),
    HMAC_SHA512 ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha512", 
                 "HS512", "HmacSHA512", HashAlgorithms.SHA512, true);

    private final String sksName;   // As expressed in SKS
    private final String joseName;  // JOSE alternative
    private final String jceName;   // As expressed for JCE
    private HashAlgorithms digestAlg; 
    private boolean sksMandatory;   // If required in SKS

    private MACAlgorithms(String sksName, String joseName, String jceName,
                          HashAlgorithms digestAlg, boolean sksMandatory) {
        this.sksName = sksName;
        this.joseName = joseName;
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

    public byte[] digest(byte[] key, byte[] data) throws IOException {
        try {
            Mac mac = Mac.getInstance(getJceName());
            mac.init(new SecretKeySpec(key, "RAW"));  // Note: any length is OK in HMAC
            return mac.doFinal(data);
        } catch (GeneralSecurityException gse) {
            throw new IOException(gse);
        }
    }

    public static boolean testAlgorithmUri(String sksName) {
        for (MACAlgorithms alg : MACAlgorithms.values()) {
            if (sksName.equals(alg.sksName)) {
                return true;
            }
        }
        return false;
    }

    public static MACAlgorithms getAlgorithmFromId(String algorithmId,
                                                   AlgorithmPreferences algorithmPreferences) 
    throws IOException {
        for (MACAlgorithms alg : values()) {
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
        throw new IOException("Unknown MAC algorithm: " + algorithmId);
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
}
