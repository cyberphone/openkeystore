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
package org.webpki.json;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;

import java.security.cert.X509Certificate;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.X509SignerInterface;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

import org.webpki.crypto.signatures.SignatureWrapper;

/**
 * Initiator object for X.509 signatures.
 */
public class JSONX509Signer extends JSONSigner {

    AsymSignatureAlgorithms algorithm;

    X509SignerInterface signer;

    X509Certificate[] certificatePath;
    
    JSONX509Signer(X509Certificate[] certificatePath) throws IOException {
        this.certificatePath = certificatePath;
        this.algorithm = KeyAlgorithms.getKeyAlgorithm(certificatePath[0].getPublicKey())
                .getRecommendedSignatureAlgorithm();
    }

    /**
     * Constructor for custom crypto solutions.
     * 
     * @param signer Handle to implementation
     * @throws IOException
     * @throws GeneralSecurityException 
     */
    public JSONX509Signer(X509SignerInterface signer) throws IOException,
                                                             GeneralSecurityException {
        this(signer.getCertificatePath());
        this.signer = signer;
    }

    /**
     * Constructor for JCE based solutions.
     * 
     * @param privateKey Private key
     * @throws IOException
     */
    public JSONX509Signer(PrivateKey privateKey, X509Certificate[] certificatePath)
            throws IOException {
        this(certificatePath);
        signer = new X509SignerInterface() {

            @Override
            public byte[] signData(byte[] data) throws IOException, GeneralSecurityException {
                return new SignatureWrapper(algorithm, privateKey, provider)
                                .update(data)
                                .sign();
            }

            @Override
            public AsymSignatureAlgorithms getAlgorithm() throws IOException,
                                                                 GeneralSecurityException {
                return algorithm;
            }

            @Override
            public X509Certificate[] getCertificatePath()
                    throws IOException, GeneralSecurityException {
                return null;  // Not used here
            }
    
        };
    }

    public JSONX509Signer setAlgorithm(AsymSignatureAlgorithms algorithm)
            throws IOException, GeneralSecurityException {
        this.algorithm = algorithm;
        return this;
    }

    public JSONX509Signer setAlgorithmPreferences(AlgorithmPreferences algorithmPreferences) {
        super.algorithmPreferences = algorithmPreferences;
        return this;
    }

    @Override
    SignatureAlgorithms getAlgorithm() throws IOException, GeneralSecurityException {
        return signer.getAlgorithm();
    }

    @Override
    byte[] signData(byte[] data) throws IOException, GeneralSecurityException {
        return signer.signData(data);
    }

    @Override
    void writeKeyData(JSONObjectWriter wr) throws IOException, GeneralSecurityException {
        wr.setCertificatePath(certificatePath);
    }
}
