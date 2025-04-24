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

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.SignatureAlgorithms;

import static org.webpki.jose.JOSEKeyWords.*;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;

import org.webpki.util.Base64URL;
import org.webpki.util.UTF8;

/**
 * JWS encoder base class
 */
public abstract class JWSSigner {
    
    JWSSigner() {}
    
    JSONObjectWriter jwsProtectedHeader;
    
    String provider;
    
    /*
     * Package level constructor
     */
    JWSSigner(SignatureAlgorithms signatureAlgorithm) {
        jwsProtectedHeader = new JSONObjectWriter()
            .setString(ALG_JSON, signatureAlgorithm.getAlgorithmId(AlgorithmPreferences.JOSE));
    }

    /**
     * Set cryptographic provider.
     * @param provider Name of provider like "BC"
     * @return JwsSigner
     */
    public JWSSigner setProvider(String provider) {
        this.provider = provider;
        return this;
    }

    /**
     * Adds "kid" to the JWS header.
     * @param keyId The key identifier to be included.
     * @return JwsSigner
     */
    public JWSSigner setKeyId(String keyId) {
        jwsProtectedHeader.setString(KID_JSON, keyId);
        return this;
    }

    /**
     * Add header elements.
     * @param items A set of JSON tokens
     * @return JwsSigner
     */
    public JWSSigner addHeaderItems(JSONObjectReader items) {
        for (String key : items.getProperties()) {
            jwsProtectedHeader.copyElement(key, key, items);
        }
        return this;
    }

    /**
     * Create JWS/CT object.
     * @param objectToBeSigned The JSON object to be signed
     * @param signatureProperty Name of property holding the "detached" JWS
     * @return The now signed <code>objectToBeSigned</code>
     */
    public JSONObjectWriter sign(JSONObjectWriter objectToBeSigned, String signatureProperty) {
        return objectToBeSigned.setString(signatureProperty, 
                                          sign(objectToBeSigned
                                                  .serializeToBytes(
                                                          JSONOutputFormats.CANONICALIZED), true));
    }

    /**
     * Create compact mode JWS object.
     * Note that the detached mode follows the specification
     * described in 
     * <a href="https://tools.ietf.org/html/rfc7515#appendix-F" 
     * target="_blank">https://tools.ietf.org/html/rfc7515#appendix-F</a>.
     * @param jwsPayload Binary payload
     * @param detached True if payload is not to be supplied in the JWS string
     * @return JWS compact (string)
     */
    public String sign(byte[] jwsPayload, boolean detached) {
        
        // Create data to be signed
        String jwsProtectedHeaderB64U = Base64URL.encode(
                jwsProtectedHeader.serializeToBytes(JSONOutputFormats.NORMALIZED));
        String jwsPayloadB64U = Base64URL.encode(jwsPayload);
        byte[] dataToBeSigned = UTF8.encode(jwsProtectedHeaderB64U + "." + jwsPayloadB64U);

        // Sign data and return JWS string
        return jwsProtectedHeaderB64U +
                "." +
                (detached ? "" : jwsPayloadB64U) +
                "." +
                Base64URL.encode(signObject(dataToBeSigned));
    }

    abstract byte[] signObject(byte[] dataToBeSigned);
}
