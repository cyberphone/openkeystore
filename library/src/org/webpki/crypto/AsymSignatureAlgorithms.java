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

import java.security.spec.MGF1ParameterSpec;

public enum AsymSignatureAlgorithms implements SignatureAlgorithms {

    RSA_NONE      ("https://webpki.github.io/sks/algorithm#rsa.pkcs1.none",  null,
                   null,                    "NONEwithRSA",     null,
                   true,  KeyTypes.RSA,   null),
      
    RSA_SHA1      ("http://www.w3.org/2000/09/xmldsig#rsa-sha1",             null,              
                   "1.2.840.113549.1.1.5",  "SHA1withRSA",     HashAlgorithms.SHA1,
                   false, KeyTypes.RSA,   null),
      
    RSA_SHA256    ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",      "RS256",      
                   "1.2.840.113549.1.1.11", "SHA256withRSA",   HashAlgorithms.SHA256, 
                   true,  KeyTypes.RSA,   null),
      
    RSA_SHA384    ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",      "RS384",     
                   "1.2.840.113549.1.1.12", "SHA384withRSA",   HashAlgorithms.SHA384, 
                   true,  KeyTypes.RSA,   null),
      
    RSA_SHA512    ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",      "RS512",   
                   "1.2.840.113549.1.1.13", "SHA512withRSA",   HashAlgorithms.SHA512,
                   true,  KeyTypes.RSA,   null),
      
    RSAPSS_SHA256 ("http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1", "PS256",      
                   "1.2.840.113549.1.1.10", "RSASSA-PSS",      HashAlgorithms.SHA256, 
                   true,  KeyTypes.RSA,   MGF1ParameterSpec.SHA256),

    RSAPSS_SHA384 ("http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1", "PS384",     
                   "1.2.840.113549.1.1.10", "RSASSA-PSS",      HashAlgorithms.SHA384, 
                   true,  KeyTypes.RSA,   MGF1ParameterSpec.SHA384),

    RSAPSS_SHA512 ("http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1", "PS512",   
                   "1.2.840.113549.1.1.10", "RSASSA-PSS",      HashAlgorithms.SHA512,
                   true,  KeyTypes.RSA,   MGF1ParameterSpec.SHA512),

    ECDSA_NONE    ("https://webpki.github.io/sks/algorithm#ecdsa.none",     null,
                   null,                    "NONEwithECDSA",   null,                  
                   true,  KeyTypes.EC,    null),
      
    ECDSA_SHA256  ("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",    "ES256",  
                   "1.2.840.10045.4.3.2",   "SHA256withECDSA", HashAlgorithms.SHA256,
                   true,  KeyTypes.EC,    null),
      
    ECDSA_SHA384  ("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",    "ES384",   
                   "1.2.840.10045.4.3.3",   "SHA384withECDSA", HashAlgorithms.SHA384, 
                   true,  KeyTypes.EC,    null),
      
    ECDSA_SHA512  ("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",    "ES512",   
                   "1.2.840.10045.4.3.4",   "SHA512withECDSA", HashAlgorithms.SHA512, 
                   true,  KeyTypes.EC,    null),

    ED25519       ("https://webpki.github.io/sks/algorithm#ed25519",         "Ed25519",   
                   "1.3.101.112",           "Ed25519",         null /*"pure" */,
                   false, KeyTypes.EDDSA, null),

    ED448         ("https://webpki.github.io/sks/algorithm#ed448",           "Ed448",   
                   "1.3.101.113",           "Ed448",           null /*"pure" */,
                   false, KeyTypes.EDDSA, null);

    private final String sksName;           // As expressed in SKS
    private final String joseName;          // Alternative JOSE name
    private final String oid;               // As expressed in OIDs
    private final String jceName;           // As expressed for JCE
    private final HashAlgorithms digestAlg; // RSA and ECDSA
    private final boolean sksMandatory;     // If required in SKS
    private final KeyTypes keyType;         // Core type
    private final MGF1ParameterSpec mgf1;   // For RSA PSS

    private AsymSignatureAlgorithms(String sksName,
                                    String joseName,
                                    String oid,
                                    String jceName,
                                    HashAlgorithms digestAlg,
                                    boolean sksMandatory,
                                    KeyTypes keyType,
                                    MGF1ParameterSpec mgf1) {
        this.sksName = sksName;
        this.joseName = joseName;
        this.oid = oid;
        this.jceName = jceName;
        this.digestAlg = digestAlg;
        this.sksMandatory = sksMandatory;
        this.keyType = keyType;
        this.mgf1 = mgf1;
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
        return oid;
    }

    @Override
    public HashAlgorithms getDigestAlgorithm() {
        return digestAlg;
    }

    public static boolean testAlgorithmUri(String sksName) {
        for (AsymSignatureAlgorithms alg : values()) {
            if (sksName.equals(alg.sksName)) {
                return true;
            }
        }
        return false;
    }

    public static AsymSignatureAlgorithms getAlgorithmFromId(String algorithmId,
                                                             AlgorithmPreferences algorithmPreferences)
    throws IOException {
        for (AsymSignatureAlgorithms alg : AsymSignatureAlgorithms.values()) {
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
        throw new IOException("Unknown signature algorithm: " + algorithmId);
    }

    @Override
    public String getAlgorithmId(AlgorithmPreferences algorithmPreferences) throws IOException {
        if (joseName == null) {
            if (algorithmPreferences == AlgorithmPreferences.JOSE) {
                throw new IOException("There is no JOSE algorithm for: " + this.toString());
            }
            return sksName;
        } else if (sksName == null) {
            if (algorithmPreferences == AlgorithmPreferences.SKS) {
                throw new IOException("There is no SKS algorithm for: " + this.toString());
            }
            return joseName;
        }
        return algorithmPreferences == AlgorithmPreferences.SKS ? sksName : joseName;
    }

    @Override
    public boolean isDeprecated() {
        return RSA_SHA1 == this;
    }

    @Override
    public KeyTypes getKeyType() {
        return keyType;
    }

    public MGF1ParameterSpec getMGF1ParameterSpec() {
        return mgf1;
    }
}
