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
import java.security.PublicKey;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.SignatureWrapper;

/**
 * JWS asymmetric key signature validator
 */
public class JWSAsymSignatureValidator extends JWSValidator {
    
    PublicKey publicKey;
    
    /**
     * Initialize validator.
     * 
     * Note that a validator object may be used any number of times
     * (assuming that the same parameters are valid).  It is also
     * thread-safe.
     * @param publicKey The anticipated public key
     */
    public JWSAsymSignatureValidator(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    void validateObject(byte[] signedData, JWSDecoder jwsDecoder) 
            throws IOException, GeneralSecurityException {
        if (jwsDecoder.optionalPublicKey != null && 
            !jwsDecoder.optionalPublicKey.equals(publicKey)) {
                throw new GeneralSecurityException(
                        "Supplied validation key differs from the signature key specified in the JWS header");
        }
        AsymSignatureAlgorithms algorithm = 
                (AsymSignatureAlgorithms) jwsDecoder.signatureAlgorithm;
        if (!new SignatureWrapper(algorithm, publicKey, provider)
                .update(signedData)
                .verify(jwsDecoder.signature)) {
            throw new GeneralSecurityException("Signature did not validate for key: " + 
                                               publicKey.toString());
        }
        JWSSigner.checkEcJwsCompliance(publicKey, algorithm);
    }
}
