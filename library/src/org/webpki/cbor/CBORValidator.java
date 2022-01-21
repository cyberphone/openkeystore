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

/**
 * Base class for CBOR signature validation
 * 
 */
public abstract class CBORValidator {
    
    CBORValidator() {}

    abstract void validate(CBORMap signatureObject, 
                           int coseAlgorithmId,
                           CBORObject optionalKeyId,
                           byte[] signatureValue,
                           byte[] signedData) throws IOException, GeneralSecurityException;
 
    /**
     * Validate signed CBOR map.
     * 
     * @param key Key in map holding signature
     * @param signedObject Signed CBOR map object
     * @return The signed object
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public CBORMap validate(CBORObject key, CBORMap signedObject) throws IOException, 
                                                                         GeneralSecurityException {
        // Fetch signature object
        CBORMap signatureObject = signedObject.getObject(key).getMap();

        // Get the signature value and remove it from the (map) object.
        byte[] signatureValue = CBORValidator.readAndRemove(signatureObject, 
                                                            CBORSigner.SIGNATURE_LABEL);

        // Fetch optional keyId.
        CBORObject optionalKeyId = signatureObject.hasKey(CBORSigner.KEY_ID_LABEL) ?
                signatureObject.getObject(CBORSigner.KEY_ID_LABEL).scan() : null;

        // Call specific validator. This code presumes that internalEncode() 
        // returns a deterministic representation of CBOR items.
        validate(signatureObject,
                 signatureObject.getObject(CBORSigner.ALGORITHM_LABEL).getInt(),
                 optionalKeyId, 
                 signatureValue,
                 signedObject.internalEncode());

        // Check that nothing "extra" was supplied.
        signatureObject.checkForUnread();

        // Restore object.
        signatureObject.keys.put(CBORSigner.SIGNATURE_LABEL, new CBORByteString(signatureValue));
        
        // Return it as well.
        return signedObject;
    }

    /**
     * Validate signed CBOR map.
     * 
     * @param key Key in map holding signature
     * @param signedObject Signed CBOR map object
     * @return The signed object
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public CBORMap validate(int key, CBORMap signedObject) throws IOException, 
                                                                  GeneralSecurityException {
        return validate(new CBORInteger(key), signedObject);
    }
    
    /**
     * Validate signed CBOR map.
     * 
     * @param key Key in map holding signature
     * @param signedObject Signed CBOR map object
     * @return The signed object
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public CBORMap validate(String key, CBORMap signedObject) throws IOException, 
                                                                     GeneralSecurityException {
        return validate(new CBORTextString(key), signedObject);
    }

    static byte[] readAndRemove(CBORMap object, CBORInteger key) throws IOException {
        byte[] data = object.getObject(key).getByteString();
        object.removeObject(key);
        return data;
    }
}
