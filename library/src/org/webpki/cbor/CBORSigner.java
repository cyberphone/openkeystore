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
package org.webpki.cbor;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

/**
 * Base class for creating CBOR signatures.
 * 
 * It uses COSE algorithms but not the packaging.

 */
public abstract class CBORSigner {

    /**
     * Integer value: 1
     */
    public static final CBORInteger ALGORITHM_LABEL  = new CBORInteger(1);
    
    /**
     * Integer value: 2
     */
    public static final CBORInteger PUBLIC_KEY_LABEL = new CBORInteger(2);
    
    /**
     * Integer value: 3
     */
    public static final CBORInteger KEY_ID_LABEL     = new CBORInteger(3);
    
    /**
     * Integer value: 4
     */
    public static final CBORInteger CERT_PATH_LABEL  = new CBORInteger(4);
    
    /**
     * Integer value: 5
     */
    public static final CBORInteger SIGNATURE_LABEL  = new CBORInteger(5);
 
    // Set by implementing classes
    String provider;
    
    PublicKey publicKey;
    
    int coseAlgorithmId;
    
    // Optional key ID
    byte[] keyId;

    CBORSigner() {}
    
    abstract byte[] signData(byte[] dataToSign) throws IOException, GeneralSecurityException;
    
    /**
     * Set signature key Id.
     * 
     * In the case the public key is not provided in the signature
     * object, the signature key may be tied to an identifier
     * known by the relying party.  How such an identifier
     * is used to retrieve the proper public key is up to a
     * convention between the parties using
     * a specific message scheme.  A keyId may be a database
     * index, a hash of the public key, a text string,
     * or a URL pointing to a Web server holding a public key
     * in PEM format.
     * <p>
     * For HMAC-signatures, a keyId or implicit key are
     * the only ways to retrieve the proper secret key.
     * </p>
     * 
     * @param keyId A key Id byte array
     * @return this
     */
    public CBORSigner setKeyId(byte[] keyId) {
        this.keyId = keyId;
        return this;
    }

    /**
     * Set cryptographic provider.
     * 
     * @param provider Name of provider like "BC"
     * @return CBORSigner
     */
    public CBORSigner setProvider(String provider) {
        this.provider = provider;
        return this;
    }

    void sign(CBORObject key, CBORMap objectToSign) throws IOException, GeneralSecurityException {

        // Create empty signature object.
        CBORMap signatureObject = new CBORMap();
        
        // Add the mandatory signature algorithm.
        signatureObject.setObject(ALGORITHM_LABEL, new CBORInteger(coseAlgorithmId));
        
        // If a public key has been defined, add it to the signature object.
        if (publicKey != null) {
            signatureObject.setObject(PUBLIC_KEY_LABEL, CBORPublicKey.encode(publicKey));
        }

        // Add a keyId if there is one.
        if (keyId != null) {
            signatureObject.setObject(KEY_ID_LABEL, new CBORByteString(keyId));
        }

        // Add the prepared signature object to the object we want to sign. 
        objectToSign.setObject(key, signatureObject);

        // Finally, sign all but the signature label and associated value.
        // encode() is supposed to produce a deterministic representation.
        signatureObject.keys.put(SIGNATURE_LABEL, 
                                 new CBORByteString(signData(objectToSign.internalEncode())));
    }
}
