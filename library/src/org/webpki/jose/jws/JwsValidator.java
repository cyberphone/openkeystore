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

import org.webpki.util.Base64URL;

/**
 * JWS validator base class
 */
public abstract class JwsValidator {
    
    String provider;

    JwsValidator() {}
    
    abstract void validate(byte[] signedData, JwsDecoder jwsDecoder) 
            throws IOException, GeneralSecurityException;

    /**
     * Set cryptographic provider
     * @param provider Name of provider like "BC"
     * @return this
     */
    public JwsValidator setProvider(String provider) {
        this.provider = provider;
        return this;
    }
    
    /**
     * Validate compact JWS signature
     * @param jwsDecoder Decoded header and string
     * @param optionalJwsPayload Must be supplied for detached mode, null otherwise
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public void validateSignature(JwsDecoder jwsDecoder, byte[] optionalJwsPayload) 
            throws IOException, GeneralSecurityException {

        // Dealing with detached and in-line
        String jwsPayloadB64U;
        if (jwsDecoder.optionalJwsPayloadB64U == null) {
            if (optionalJwsPayload == null) {
                throw new IllegalArgumentException("Detached payload missing");
            }
            jwsPayloadB64U = Base64URL.encode(optionalJwsPayload);
        } else {
            if (optionalJwsPayload != null) {
                throw new IllegalArgumentException(
                        "Both external and JWS-supplied payload? Set argument to \"null\"");
            }
            jwsPayloadB64U = jwsDecoder.optionalJwsPayloadB64U;
        }
        
        // Delegated validation
        validate((jwsDecoder.jwsProtectedHeaderB64U + "." + jwsPayloadB64U).getBytes("utf-8"),
                 jwsDecoder);
    }
}
