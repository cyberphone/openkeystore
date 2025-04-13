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
package org.webpki.cbor;

import org.webpki.cbor.CBORCryptoUtils.POLICY;
import org.webpki.cbor.CBORCryptoUtils.Collector;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Base class for validating signatures.
 * <p>
 * See also {@link CBORSigner}.
 * </p>
 * <p>
 * Note that validator objects may be used any number of times
 * (assuming that the same parameters are valid).  They are also
 * thread-safe.
 * </p>
 */
public abstract class CBORValidator <T extends CBORValidator<T>> {
    
    CBORValidator() {}

    abstract void coreValidation(CBORMap csfContainer, 
                                 int coseAlgorithmId,
                                 CBORObject optionalKeyId,
                                 byte[] signatureValue,
                                 byte[] signedData);

    abstract T getThis();
 
    POLICY customDataPolicy = POLICY.FORBIDDEN;
    Collector customDataCollector;
    

    /**
     * Sets custom data policy.
     * <p>
     * By default custom data elements ({@link CBORCryptoConstants#CXF_CUSTOM_DATA_LBL}) 
     * are rejected ({@link CBORCryptoUtils.POLICY#FORBIDDEN}).
     * </p>
     * <p>
     * See also <a href='doc-files/crypto-options.html'>crypto options</a>.
     * </p>
     * @param customDataPolicy Define level of support
     * @param customDataCollector Interface for reading custom data
     * @return <code>this</code> of subclass
     */
    public T setCustomDataPolicy(POLICY customDataPolicy, Collector customDataCollector) {
        this.customDataPolicy = customDataPolicy;
        this.customDataCollector = customDataCollector;
        return getThis();
    }

    POLICY tagPolicy = POLICY.FORBIDDEN;
    Collector tagCollector;

    /**
     * Sets tag wrapping policy.
     * <p>
     * By default tagged CSF containers are rejected ({@link CBORCryptoUtils.POLICY#FORBIDDEN}).
     * </p>
     * <p>
     * See also <a href='doc-files/crypto-options.html'>crypto options</a>.
     * </p>
     * @param tagPolicy Define level of support
     * @param tagCollector Interface for reading tag
     * @return <code>this</code> of subclass
     */
    public T setTagPolicy(POLICY tagPolicy, Collector tagCollector) {
        this.tagPolicy = tagPolicy;
        this.tagCollector = tagCollector;
        return getThis();
    }

    /**
     * Validates signed CBOR object.
     * <p>
     * This method presumes that <code>signedObject</code> holds
     * an enveloped signature according to CSF.
     * </p>
     * 
     * @param csfContainerLabel Label (key) in the map holding the signature
     * @param signedObject Signed CBOR object
     * @return The original <code>signedObject</code>
     */
    public CBORObject validate(CBORObject csfContainerLabel, CBORObject signedObject) {

        // There may be a tag holding the signed map.
        CBORMap signedMap = CBORCryptoUtils.unwrapContainerMap(signedObject,
                                                               tagPolicy,
                                                               tagCollector);

        // Fetch signature container object
        CBORMap csfContainer = signedMap.get(csfContainerLabel).getMap();

        // Get the signature value and remove it from the (map) object.
        byte[] signatureValue = csfContainer.remove(CSF_SIGNATURE_LBL).getBytes();

        // Fetch optional keyId.
        CBORObject optionalKeyId = CBORCryptoUtils.getKeyId(csfContainer);

        // Special handling of custom data.
        CBORCryptoUtils.getCustomData(csfContainer, customDataPolicy, customDataCollector);

        // Call algorithm specific validator. The code below presumes that encode()
        // returns a deterministic representation of the signed CBOR data.
        coreValidation(csfContainer,
                       csfContainer.get(CXF_ALGORITHM_LBL).getInt32(),
                       optionalKeyId, 
                       signatureValue,
                       signedObject.encode());

        // Check that nothing "extra" was supplied.
        csfContainer.checkForUnread();

        // Restore object.
        csfContainer.set(CSF_SIGNATURE_LBL, new CBORBytes(signatureValue));
        
        // Return it as well.
        return signedObject;
    }
}
