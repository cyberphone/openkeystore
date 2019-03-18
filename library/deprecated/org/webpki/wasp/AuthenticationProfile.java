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
package org.webpki.wasp;

import java.io.IOException;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.xmldsig.CanonicalizationAlgorithms;


public class AuthenticationProfile {
    boolean signed_key_info;

    boolean extendedCertPath;

    CanonicalizationAlgorithms canonicalization_algorithm;

    HashAlgorithms digest_algorithm;

    AsymSignatureAlgorithms signatureAlgorithm;

    AuthenticationProfile() {
    }

    public boolean getSignedKeyInfo() {
        return signed_key_info;
    }

    public boolean getExtendedCertPath() {
        return extendedCertPath;
    }

    public CanonicalizationAlgorithms getCanonicalizationAlgorithm() {
        return canonicalization_algorithm;
    }

    public HashAlgorithms getDigestAlgorithm() {
        return digest_algorithm;
    }

    public AsymSignatureAlgorithms getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignedKeyInfo(boolean flag) {
        this.signed_key_info = flag;
    }

    public void setExtendedCertPath(boolean flag) {
        this.extendedCertPath = flag;
    }

    public void setCanonicalizationAlgorithm(CanonicalizationAlgorithms canonicalization_algorithm) {
        canonicalization_algorithm.getURI();
        this.canonicalization_algorithm = canonicalization_algorithm;
    }

    public void setDigestAlgorithm(HashAlgorithms digest_algorithm) {
        digest_algorithm.getAlgorithmId();
        this.digest_algorithm = digest_algorithm;
    }

    public void setSignatureAlgorithm(AsymSignatureAlgorithms signatureAlgorithm) throws IOException {
        signatureAlgorithm.getAlgorithmId(AlgorithmPreferences.SKS);
        this.signatureAlgorithm = signatureAlgorithm;
    }
}
