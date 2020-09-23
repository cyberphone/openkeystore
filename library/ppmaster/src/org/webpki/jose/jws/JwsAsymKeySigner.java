/*
 *  Copyright 2018-2020 WebPKI.org (http://webpki.org).
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
package org.webpki.jose.jws;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

//#if ANDROID
import android.util.Base64;
//#else
import java.util.Base64;
//#endif

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.SignatureWrapper;

import static org.webpki.jose.JoseKeyWords.*;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectWriter;

/**
 * Creates asymmetric key signatures
 */
public class JwsAsymKeySigner extends JwsSigner {
    
    PrivateKey privateKey;
    AsymSignatureAlgorithms signatureAlgorithm;
    
    /**
     * Create signer
     * @param privateKey The key to sign with
     * @param signatureAlgorithm The algorithm to use
     * @throws IOException 
     */
    public JwsAsymKeySigner(PrivateKey privateKey, 
                            AsymSignatureAlgorithms signatureAlgorithm) throws IOException {
         super(signatureAlgorithm);
         this.privateKey = privateKey;
         this.signatureAlgorithm = signatureAlgorithm;
    }
    
    /**
     * Adds "jwk" to the JWS header
     * @param publicKey The public key to be included
     * @throws IOException 
     */
    public JwsAsymKeySigner setPublicKey(PublicKey publicKey) throws IOException {
        jwsProtectedHeader.setObject(JWK_JSON, 
                                     JSONObjectWriter.createCorePublicKey(
                                             publicKey,
                                             AlgorithmPreferences.JOSE));

        return this;
    }

    /**
     * Adds "x5c" to the JWS header
     * @param certificatePath The certificate(s) to be included
     * @throws IOException 
     * @throws GeneralSecurityException 
     */
    public JwsAsymKeySigner setCertificatePath(X509Certificate[] certificatePath) 
            throws IOException, GeneralSecurityException {
        JSONArrayWriter certPath = jwsProtectedHeader.setArray(X5C_JSON);
        for (X509Certificate cert : certificatePath) {
//#if ANDROID
            certPath.setString(Base64.encodeToString(cert.getEncoded(), Base64.NO_WRAP));
//#else
            certPath.setString(Base64.getEncoder().encodeToString(cert.getEncoded()));
//#endif
        }
        return this;
    }

    @Override
    void signData(byte[] dataToBeSigned) throws IOException, GeneralSecurityException {
        signature = new SignatureWrapper(signatureAlgorithm, privateKey, provider)
                .update(dataToBeSigned)
                .sign();
        checkEcJwsCompliance(privateKey, signatureAlgorithm);
        privateKey = null;
    }
}
