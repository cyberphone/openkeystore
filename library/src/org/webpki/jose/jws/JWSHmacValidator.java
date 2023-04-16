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

import java.util.Arrays;

import org.webpki.crypto.HmacAlgorithms;

/**
 * JWS HMAC signature validator
 */
public class JWSHmacValidator extends JWSValidator {
    
    byte[] secretKey;
    
    /**
     * Initialize validator.
     * 
     * Note that a validator object may be used any number of times
     * (assuming that the same parameters are valid).  It is also
     * thread-safe.
     * @param secretKey The anticipated secret key
     */
    public JWSHmacValidator(byte[] secretKey) {
        this.secretKey = secretKey;
    }

    @Override
    void validateObject(byte[] signedData, JWSDecoder jwsDecoder)
            throws IOException, GeneralSecurityException {
        if (!Arrays.equals(
               ((HmacAlgorithms)jwsDecoder.signatureAlgorithm).digest(secretKey, 
                                                                      signedData),
                                                                      jwsDecoder.signature)) {
            throw new IOException("HMAC signature validation error");
        }
    }
}
