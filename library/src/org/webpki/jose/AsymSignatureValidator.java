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
package org.webpki.jose;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import java.security.interfaces.ECKey;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.SignatureWrapper;
import org.webpki.crypto.KeyAlgorithms;

/**
 * JWS asymmetric key signature validator
 */
public class AsymSignatureValidator extends JOSESupport.CoreSignatureValidator {
    
    PublicKey publicKey;
    
    /**
     * Create validator
     * @param publicKey
     */
    public AsymSignatureValidator(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    void validate(byte[] signedData,
                  JwsDecoder jwsDecoder) throws IOException, GeneralSecurityException {
        AsymSignatureAlgorithms algorithm = 
                (AsymSignatureAlgorithms) jwsDecoder.signatureAlgorithm;
        if (!new SignatureWrapper(algorithm, publicKey)
                .update(signedData)
                .verify(jwsDecoder.signature)) {
            throw new GeneralSecurityException("Signature did not validate for key: " + 
                                               publicKey.toString());
        }
        if (publicKey instanceof ECKey) {
            if (KeyAlgorithms.getKeyAlgorithm(publicKey)
                    .getRecommendedSignatureAlgorithm() != algorithm) {
                throw new GeneralSecurityException(
                        "EC key and algorithm does not match the JWS spec");
            }
        } 
     }
}
