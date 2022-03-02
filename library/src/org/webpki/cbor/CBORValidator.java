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

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Base class for validating CBOR signatures.
 * <p>
 * This implementation supports signatures using CSF (CBOR Signature Format) packaging,
 * while algorithms are derived from COSE.
 * </p>
 * <p>
 * Note that validator objects may be used any number of times
 * (assuming that the same parameters are valid).  They are also
 * thread-safe.
 * </p>
 * @see CBORSigner
 */
public abstract class CBORValidator {
    
    CBORValidator() {}

    abstract void coreValidation(CBORMap signatureObject, 
                                 int coseAlgorithmId,
                                 CBORObject optionalKeyId,
                                 byte[] signatureValue,
                                 byte[] signedData) throws IOException, GeneralSecurityException;
 
    /**
     * Validates signed CBOR map.
     * <p>
     * This method presumes that <code>signedObject</code> holds
     * an enveloped signature according to CSF.
     * </p>
     * <p>
     * Note that if <code>signedObject</code> holds a CBOR
     * tag object the tag must in turn contain the signed map,
     * and the tag will also be included in the signed data.
     * </p>
     * @param key Key in map holding signature
     * @param signedObject Signed CBOR map object
     * @return The signed object
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public CBORObject validate(CBORObject key, CBORObject signedObject) 
            throws IOException, GeneralSecurityException {

        // There may be a tag holding the signed map.
        CBORMap signedMap = CBORCryptoUtils.getContainerMap(signedObject);

        // Fetch signature object
        CBORMap signatureObject = signedMap.getObject(key).getMap();

        // Get the signature value and remove it from the (map) object.
        byte[] signatureValue = signatureObject.readByteStringAndRemoveKey(SIGNATURE_LABEL);

        // Fetch optional keyId.
        CBORObject optionalKeyId = signatureObject.hasKey(KEY_ID_LABEL) ?
                         signatureObject.getObject(KEY_ID_LABEL).scan() : null;

        // Call algorithm specific validator. The code below presumes that internalEncode()
        // returns a deterministic representation of the signed CBOR data.
        coreValidation(signatureObject,
                       signatureObject.getObject(ALGORITHM_LABEL).getInt(),
                       optionalKeyId, 
                       signatureValue,
                       signedObject.internalEncode());

        // Check that nothing "extra" was supplied.
        signatureObject.checkForUnread();

        // Restore object.
        signatureObject.setObject(SIGNATURE_LABEL, new CBORByteString(signatureValue));
        
        // Return it as well.
        return signedObject;
    }

    /**
     * Validates signed CBOR map.
     * <p>
     * See {@link #validate(CBORObject, CBORMap)} for details.
     * </p>
     * 
     * @param key Key in map holding signature
     * @param signedObject Signed CBOR map object
     * @return The signed object
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public CBORObject validate(int key, CBORObject signedObject) throws IOException, 
                                                                        GeneralSecurityException {
        return validate(new CBORInteger(key), signedObject);
    }
    
    /**
     * Validates signed CBOR map.
     * <p>
     * See {@link #validate(CBORObject, CBORMap)} for details.
     * </p>
     * 
     * @param key Key in map holding signature
     * @param signedObject Signed CBOR map object
     * @return The signed object
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public CBORObject validate(String key, CBORObject signedObject) throws IOException, 
                                                                           GeneralSecurityException {
        return validate(new CBORTextString(key), signedObject);
    }
}
