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

import org.webpki.cbor.CBORCryptoUtils.POLICY;
import org.webpki.cbor.CBORCryptoUtils.Collector;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Base class for validating signatures.
 * <p>
 * See {@link CBORSigner} for details.
 * </p>
 * <p>
 * Note that validator objects may be used any number of times
 * (assuming that the same parameters are valid).  They are also
 * thread-safe.
 * </p>
 */
public abstract class CBORValidator {
    
    CBORValidator() {}

    abstract void coreValidation(CBORMap signatureObject, 
                                 int coseAlgorithmId,
                                 CBORObject optionalKeyId,
                                 byte[] signatureValue,
                                 byte[] signedData) throws IOException, GeneralSecurityException;
 
    POLICY customDataPolicy = POLICY.FORBIDDEN;
    Collector customDataCollector;
    

    /**
     * Sets custom data policy.
     * <p>
     * By default custom data elements ({@link CBORCryptoConstants#CUSTOM_DATA_LABEL}) 
     * are rejected ({@link CBORCryptoUtils.POLICY#FORBIDDEN}).
     * </p>
     * <p>
     * See <a href='doc-files/crypto-options.html'>crypto options</a> for details.
     * </p>
     * @param customDataPolicy Define level of support
     * @param customDataCollector Interface for reading custom data
     * @return <code>this</code>
     */
    public CBORValidator setCustomDataPolicy(POLICY customDataPolicy, 
                                             Collector customDataCollector) {
        this.customDataPolicy = customDataPolicy;
        this.customDataCollector = customDataCollector;
        return this;
    }

    POLICY tagPolicy = POLICY.FORBIDDEN;
    Collector tagCollector;

    /**
     * Sets tag wrapping policy.
     * <p>
     * By default tagged CSF containers are rejected ({@link CBORCryptoUtils.POLICY#FORBIDDEN}).
     * </p>
     * <p>
     * See <a href='doc-files/crypto-options.html'>crypto options</a> for details.
     * </p>
     * @param tagPolicy Define level of support
     * @param tagCollector Interface for reading tag
     * @return <code>this</code>
     */
    public CBORValidator setTagPolicy(POLICY tagPolicy, Collector tagCollector) {
        this.tagPolicy = tagPolicy;
        this.tagCollector = tagCollector;
        return this;
    }

    /**
     * Validates signed CBOR object.
     * <p>
     * This method presumes that <code>signedObject</code> holds
     * an enveloped signature according to CSF.
     * </p>
     * 
     * @param key Key in map holding signature
     * @param signedObject Signed CBOR object
     * @return The original <code>signedObject</code>
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public CBORObject validate(CBORObject key, CBORObject signedObject) 
            throws IOException, GeneralSecurityException {

        // There may be a tag holding the signed map.
        CBORMap signedMap = CBORCryptoUtils.unwrapContainerMap(signedObject,
                                                               tagPolicy,
                                                               tagCollector);

        // Fetch signature container object
        CBORMap csfContainer = signedMap.getObject(key).getMap();

        // Get the signature value and remove it from the (map) object.
        byte[] signatureValue = csfContainer.readByteStringAndRemoveKey(SIGNATURE_LABEL);

        // Fetch optional keyId.
        CBORObject optionalKeyId = CBORCryptoUtils.getKeyId(csfContainer);

        // Special handling of custom data.
        CBORCryptoUtils.getCustomData(csfContainer, customDataPolicy, customDataCollector);

        // Call algorithm specific validator. The code below presumes that internalEncode()
        // returns a deterministic representation of the signed CBOR data.
        coreValidation(csfContainer,
                       csfContainer.getObject(ALGORITHM_LABEL).getInt(),
                       optionalKeyId, 
                       signatureValue,
                       signedObject.encode());

        // Check that nothing "extra" was supplied.
        csfContainer.checkForUnread();

        // Restore object.
        csfContainer.setObject(SIGNATURE_LABEL, new CBORByteString(signatureValue));
        
        // Return it as well.
        return signedObject;
    }

    /**
     * Validates signed CBOR object.
     * <p>
     * See {@link #validate(CBORObject, CBORObject)} for details.
     * </p>
     * 
     * @param key Key in map holding signature
     * @param signedObject Signed CBOR object
     * @return The original <code>signedObject</code>
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public CBORObject validate(int key, CBORObject signedObject) throws IOException, 
                                                                        GeneralSecurityException {
        return validate(new CBORInteger(key), signedObject);
    }
    
    /**
     * Validates signed CBOR object.
     * <p>
     * See {@link #validate(CBORObject, CBORObject)} for details.
     * </p>
     * 
     * @param key Key in map holding signature
     * @param signedObject Signed CBOR object
     * @return The original <code>signedObject</code>
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public CBORObject validate(String key, CBORObject signedObject) throws IOException, 
                                                                           GeneralSecurityException {
        return validate(new CBORTextString(key), signedObject);
    }
}
