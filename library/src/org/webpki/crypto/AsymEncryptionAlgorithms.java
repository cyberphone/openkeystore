/*
 *  Copyright 2006-2018 WebPKI.org (http://webpki.org).
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


public enum AsymEncryptionAlgorithms implements EncryptionAlgorithms {

    RSA_ES_PKCS_1_5        ("http://xmlns.webpki.org/sks/algorithm#rsa.es.pkcs1_5",
                            null,
                            "1.2.840.113549.1.1.1",
                            "RSA/ECB/PKCS1Padding"),
    
    RSA_OAEP_SHA1_MGF1P    ("http://xmlns.webpki.org/sks/algorithm#rsa.oaep.sha1.mgf1p",
                            "RSA-OAEP",
                            null,
                            "RSA/ECB/OAEPWithSHA-1AndMGF1Padding"),
    
    RSA_OAEP_SHA256_MGF1P  ("http://xmlns.webpki.org/sks/algorithm#rsa.oaep.sha256.mgf1p",
                            "RSA-OAEP-256",
                            null,                            
                            "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"),
    
    RSA_RAW                ("http://xmlns.webpki.org/sks/algorithm#rsa.raw",
                            null,
                            null,
                            "RSA/ECB/NoPadding");

    private final String sksName;      // As expressed in SKS
    private final String joseName;     // Alternative JOSE name
    private final String oid;          // As expressed in OIDs
    private final String jceName;      // As expressed for JCE

    private AsymEncryptionAlgorithms(String sksName, String joseName, String oid, String jceName) {
        this.sksName = sksName;
        this.joseName = joseName;
        this.oid = oid;
        this.jceName = jceName;
    }


    @Override
    public boolean isSymmetric() {
        return false;
    }


    @Override
    public boolean isMandatorySksAlgorithm() {
        return this != RSA_OAEP_SHA1_MGF1P;
    }


    @Override
    public String getJceName() {
        return jceName;
    }


    @Override
    public String getOid() {
        return oid;
    }


    public static AsymEncryptionAlgorithms getAlgorithmFromOid(String oid) throws IOException {
        for (AsymEncryptionAlgorithms alg : values()) {
            if (oid.equals(alg.oid)) {
                return alg;
            }
        }
        throw new IOException("Unknown algorithm: " + oid);
    }


    public static AsymEncryptionAlgorithms getAlgorithmFromId(String algorithmId,
                                                              AlgorithmPreferences algorithmPreferences) throws IOException {
        for (AsymEncryptionAlgorithms alg : values()) {
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
        return this == RSA_ES_PKCS_1_5;
    }
}
