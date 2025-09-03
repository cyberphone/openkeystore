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

import java.security.MessageDigest;
import java.security.GeneralSecurityException;

/**
 * Hash algorithms including an implementation.
 *
 */
public enum HashAlgorithms implements CryptoAlgorithms {

    SHA1   ("http://www.w3.org/2000/09/xmldsig#sha1",        null,
            -14, "1.3.14.3.2.26",          "SHA-1",   20),

    SHA256 ("http://www.w3.org/2001/04/xmlenc#sha256",       "S256",
            -16, "2.16.840.1.101.3.4.2.1", "SHA-256", 32),

    SHA384 ("http://www.w3.org/2001/04/xmldsig-more#sha384", "S384",
            -43, "2.16.840.1.101.3.4.2.2", "SHA-384", 48),

    SHA512 ("http://www.w3.org/2001/04/xmlenc#sha512",       "S512",
            -44, "2.16.840.1.101.3.4.2.3", "SHA-512", 64);

    private final String sksName;   // As expressed in SKS
    private final String joseName;  // Alternative JOSE name
    private final int    coseId;    // COSE
    private final String oid;       // As expressed in ASN.1 messages
    private final String jceName;   // As expressed for JCE
    private final int    bytes;     // Get number of bytes in result

    private HashAlgorithms(String sksName, 
                           String joseName, 
                           int coseId,
                           String oid, 
                           String jceName,

                           int bytes) {
        this.sksName = sksName;
        this.joseName = joseName;
        this.coseId = coseId;
        this.oid = oid;
        this.jceName = jceName;
        this.bytes = bytes;
    }

    @Override
    public String getJceName() {
        return jceName;
    }

    public byte[] digest(byte[] data) {
        try {
            return MessageDigest.getInstance(getJceName()).digest(data);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        }
    }
 
    @Override
    public int getCoseAlgorithmId() {
        return coseId;
    }

    public static HashAlgorithms getAlgorithmFromOid(String oid) {
        for (HashAlgorithms alg : values()) {
            if (oid.equals(alg.oid)) {
                return alg;
            }
        }
        throw new CryptoException("Unknown algorithm: " + oid);
    }

    public static HashAlgorithms getAlgorithmFromId(String algorithmId,
                                                    AlgorithmPreferences algorithmPreferences) {
        for (HashAlgorithms alg : values()) {
            if (algorithmId.equals(alg.sksName)) {
                if (algorithmPreferences == AlgorithmPreferences.JOSE) {
                    throw new CryptoException(
                            "JOSE algorithm expected: " + algorithmId);
                }
                return alg;
            }
            if (algorithmId.equals(alg.joseName)) {
                if (algorithmPreferences == AlgorithmPreferences.SKS) {
                    throw new CryptoException(
                            "SKS algorithm expected: " + algorithmId);
                }
                return alg;
            }
        }
        throw new CryptoException("Unknown algorithm: " + algorithmId);
    }
    
    @Override
    public boolean isMandatorySksAlgorithm() {
        return false;
    }

    @Override
    public String getAlgorithmId(AlgorithmPreferences algorithmPreferences) {
        if (joseName == null) {
            if (algorithmPreferences == AlgorithmPreferences.JOSE) {
                throw new CryptoException("There is no JOSE algorithm for: " +  this.toString());
            }
            return sksName;
        }
        return algorithmPreferences == AlgorithmPreferences.SKS ? sksName : joseName;
    }

    @Override
    public String getOid() {
        return oid;
    }

    @Override
    public boolean isSymmetric() {
         return true;
    }

    @Override
    public boolean isDeprecated() {
        return this == SHA1;
    }

    @Override
    public KeyTypes getKeyType() {
        return KeyTypes.SYM;
    }

    public int getResultBytes() {
        return bytes;
    }
}
