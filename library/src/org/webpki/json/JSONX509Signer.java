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
package org.webpki.json;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;

import java.security.cert.X509Certificate;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SignatureWrapper;
import org.webpki.crypto.SignerInterface;

/**
 * Initiator object for X.509 signatures.
 */
public class JSONX509Signer extends JSONSigner {

    private static final long serialVersionUID = 1L;

    AsymSignatureAlgorithms algorithm;

    SignerInterface signer;

    X509Certificate[] certificatePath;

    /**
     * Constructor for custom crypto solutions.
     * @param signer Handle to implementation
     * @throws IOException &nbsp;
     */
    public JSONX509Signer(SignerInterface signer) throws IOException {
        this.signer = signer;
        certificatePath = CertificateUtil.checkCertificatePath(signer.getCertificatePath());
        algorithm = KeyAlgorithms.getKeyAlgorithm(certificatePath[0].getPublicKey()).getRecommendedSignatureAlgorithm();
    }

    /**
     * Constructor for JCE based solutions.
     * @param privateKey Private key
     * @param certificatePath Certificate path
     * @param provider Optional JCE provider or null
     * @throws IOException &nbsp;
     */
    public JSONX509Signer(final PrivateKey privateKey,
                          final X509Certificate[] certificatePath,
                          final String provider) throws IOException {
        this(new SignerInterface() {

            @Override
            public X509Certificate[] getCertificatePath() throws IOException {
                return certificatePath;
            }

            @Override
            public byte[] signData(byte[] data, AsymSignatureAlgorithms algorithm) throws IOException {
                try {
                    return new SignatureWrapper(algorithm, privateKey, provider).update(data).sign();
                } catch (GeneralSecurityException e) {
                    throw new IOException(e);
                }
            }
            
        });
    }

    public JSONX509Signer setSignatureAlgorithm(AsymSignatureAlgorithms algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public JSONX509Signer setAlgorithmPreferences(AlgorithmPreferences algorithmPreferences) {
        super.algorithmPreferences = algorithmPreferences;
        return this;
    }

    @Override
    SignatureAlgorithms getAlgorithm() {
        return algorithm;
    }

    @Override
    byte[] signData(byte[] data) throws IOException {
        return signer.signData(data, algorithm);
    }

    @Override
    void writeKeyData(JSONObjectWriter wr) throws IOException {
        wr.setCertificatePath(certificatePath);
    }
}
