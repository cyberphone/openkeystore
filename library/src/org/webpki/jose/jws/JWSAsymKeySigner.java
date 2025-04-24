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
package org.webpki.jose.jws;

import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.util.Base64;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.SignatureWrapper;

import static org.webpki.jose.JOSEKeyWords.*;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectWriter;

/**
 * JWS asymmetric key signer
 */
public class JWSAsymKeySigner extends JWSSigner {
    
    PrivateKey privateKey;
    AsymSignatureAlgorithms signatureAlgorithm;
    
    /**
     * Initialize signer.
     * 
     * Note that a signer object may be used any number of times
     * (assuming that the same parameters are valid).  It is also
     * thread-safe.
     * @param privateKey The key to sign with
     * @param signatureAlgorithm The algorithm to use
     */
    public JWSAsymKeySigner(PrivateKey privateKey, 
                            AsymSignatureAlgorithms signatureAlgorithm) {
        super(signatureAlgorithm);
        this.privateKey = privateKey;
        this.signatureAlgorithm = signatureAlgorithm;
    }
    
    /**
     * Initialize signer.
     * 
     * Note that a signer object may be used any number of times
     * (assuming that the same parameters are valid).  It is also
     * thread-safe.
     * The default signature algorithm to use is based on the recommendations
     * in RFC 7518.
     * @param privateKey The key to sign with
     */
    public JWSAsymKeySigner(PrivateKey privateKey) {
        this(privateKey, 
             KeyAlgorithms.getKeyAlgorithm(privateKey).getRecommendedSignatureAlgorithm());
    }
    
    /**
     * Adds "jwk" to the JWS header.
     * @param publicKey The public key to be included
     * @return JwsAsymKeySigner
     */
    public JWSAsymKeySigner setPublicKey(PublicKey publicKey) {
        jwsProtectedHeader.setObject(JWK_JSON, 
                                     JSONObjectWriter.createCorePublicKey(
                                             publicKey,
                                             AlgorithmPreferences.JOSE));

        return this;
    }

    /**
     * Adds "x5c" to the JWS header.
     * @param certificatePath The certificate(s) to be included
     * @return JwsAsymKeySigner
     */
    public JWSAsymKeySigner setCertificatePath(X509Certificate[] certificatePath) {
        JSONArrayWriter certPath = jwsProtectedHeader.setArray(X5C_JSON);
        for (X509Certificate cert : certificatePath) {
            certPath.setString(
                    Base64.getEncoder().encodeToString(CertificateUtil.getBlobFromCertificate(cert)));
        }
        return this;
    }

    @Override
    byte[] signObject(byte[] dataToBeSigned) {
        return SignatureWrapper.sign(privateKey, signatureAlgorithm, dataToBeSigned, provider);
    }
}
