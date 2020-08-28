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

import java.security.MessageDigest;
import java.security.GeneralSecurityException;

public enum HashAlgorithms implements CryptoAlgorithms {

    SHA1   ("http://www.w3.org/2000/09/xmldsig#sha1",        null,
            "1.3.14.3.2.26",          "SHA-1"),

    SHA256 ("http://www.w3.org/2001/04/xmlenc#sha256",       "S256",
            "2.16.840.1.101.3.4.2.1", "SHA-256"),

    SHA384 ("http://www.w3.org/2001/04/xmldsig-more#sha384", "S384",
            "2.16.840.1.101.3.4.2.2", "SHA-384"),

    SHA512 ("http://www.w3.org/2001/04/xmlenc#sha512",       "S512",
            "2.16.840.1.101.3.4.2.3", "SHA-512");

    private final String sksName;   // As expressed in SKS
    private final String joseName;  // Alternative JOSE name
    private final String oid;       // As expressed in ASN.1 messages
    private final String jceName;   // As expressed for JCE

    private HashAlgorithms(String sksName, String joseName, String oid, String jceName) {
        this.sksName = sksName;
        this.joseName = joseName;
        this.oid = oid;
        this.jceName = jceName;
    }

    @Override
    public String getJceName() {
        return jceName;
    }

    public byte[] digest(byte[] data) throws IOException {
        try {
            return MessageDigest.getInstance(getJceName()).digest(data);
        } catch (GeneralSecurityException gse) {
            throw new IOException(gse);
        }
    }

    public static HashAlgorithms getAlgorithmFromOid(String oid) throws IOException {
        for (HashAlgorithms alg : values()) {
            if (oid.equals(alg.oid)) {
                return alg;
            }
        }
        throw new IOException("Unknown algorithm: " + oid);
    }

    public static HashAlgorithms getAlgorithmFromId(String algorithmId,
                                                    AlgorithmPreferences algorithmPreferences)
    throws IOException {
        for (HashAlgorithms alg : values()) {
            if (algorithmId.equals(alg.sksName)) {
                if (algorithmPreferences == AlgorithmPreferences.JOSE) {
                    throw new IOException(
                            "JOSE algorithm expected: " + algorithmId);
                }
                return alg;
            }
            if (algorithmId.equals(alg.joseName)) {
                if (algorithmPreferences == AlgorithmPreferences.SKS) {
                    throw new IOException(
                            "SKS algorithm expected: " + algorithmId);
                }
                return alg;
            }
        }
        throw new IOException("Unknown algorithm: " + algorithmId);
    }
    
    @Override
    public boolean isMandatorySksAlgorithm() {
        return false;
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
}
