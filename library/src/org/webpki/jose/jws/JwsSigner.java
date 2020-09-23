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
import java.security.Key;

import java.security.interfaces.ECKey;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

import static org.webpki.jose.JoseKeyWords.*;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;

import org.webpki.util.Base64URL;

/**
 * JWS encoder base class
 */
public abstract class JwsSigner {
    
    JwsSigner() {}
    
    JSONObjectWriter jwsProtectedHeader;
    
    byte[] signature;
    
    String provider;
    
    /*
     * Package level constructor
     */
    JwsSigner(SignatureAlgorithms signatureAlgorithm) throws IOException {
        jwsProtectedHeader = new JSONObjectWriter()
            .setString(ALG_JSON,signatureAlgorithm.isOkp() ? 
                           EdDSA 
                                                           : 
                           signatureAlgorithm.getAlgorithmId(AlgorithmPreferences.JOSE));
    }

    /**
     * Set cryptographic provider
     * @param provider Name of provider like "BC"
     * @return this
     */
    public JwsSigner setProvider(String provider) {
        this.provider = provider;
        return this;
    }

    /**
     * Add header elements
     * @param items A set of JSON tokens
     * @throws IOException
     * @return this
     */
    public JwsSigner addHeaderItems(JSONObjectReader items) throws IOException {
        for (String key : items.getProperties()) {
            jwsProtectedHeader.copyElement(key, key, items);
        }
        return this;
    }
    
    /**
     * Create compact JWS signature
     * @param jwsPayload Binary payload
     * @param detached True if payload is not to be supplied in the string
     * @return JWS compact (string)
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public String createSignature(byte[] jwsPayload,
                                  boolean detached) throws IOException, GeneralSecurityException {
        
        // Create data to be signed
        String jwsProtectedHeaderB64U = Base64URL.encode(
                jwsProtectedHeader.serializeToBytes(JSONOutputFormats.NORMALIZED));
        String jwsPayloadB64U = Base64URL.encode(jwsPayload);
        byte[] dataToBeSigned = (jwsProtectedHeaderB64U + "." + jwsPayloadB64U).getBytes("utf-8");

        // Sign data
        signData(dataToBeSigned);
        
        // Disable any efforts reusing this object
        jwsProtectedHeader = null;
        
        // Return JWS string
        return jwsProtectedHeaderB64U +
                "." +
                (detached ? "" : jwsPayloadB64U) +
                "." +
                Base64URL.encode(signature);
    }

    abstract void signData(byte[] dataToBeSigned) throws IOException, GeneralSecurityException;

    /*
     * Verify that EC algorithms follow key types as specified by RFC 7515
     */
    static void checkEcJwsCompliance(Key key, AsymSignatureAlgorithms signatureAlgorithm)
            throws GeneralSecurityException, IOException {
        if (key instanceof ECKey) {
            if (KeyAlgorithms.getKeyAlgorithm(key)
                    .getRecommendedSignatureAlgorithm() != signatureAlgorithm) {
                throw new GeneralSecurityException(
                        "EC key and algorithm does not match the JWS spec");
            }
        } 
    }
}
