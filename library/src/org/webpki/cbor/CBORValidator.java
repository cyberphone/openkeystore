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

import static org.webpki.cbor.CBORInternal.*;

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

    private boolean externalInterface;

    private boolean multiSignFlag;
    
    CBORValidator(boolean externalInterface) {
        this.externalInterface = externalInterface;
    }

    abstract void coreValidation(CBORMap csfContainer, 
                                 int coseAlgorithmId,
                                 CBORObject optionalKeyId,
                                 byte[] signatureValue,
                                 byte[] signedData);

    abstract T getThis();
 
    POLICY customDataPolicy = POLICY.FORBIDDEN;
    Collector customDataCollector;
    


    /**
     * Set multiple signature mode.
     * <p>
     * By default the {@link #validate(CBORObject)} method
     * assumes single signature mode.
     * </p>
     * 
     * @param flag If <code>true</code> multiple signature mode is assumed
     * @return <code>this</code> of subclass
     */
    public T setMultiSignatureMode(boolean flag) {
        if ((multiSignFlag = flag) && !externalInterface) {
            cborError("multi signature validation requires the external interface of the validation class");
        }
        return getThis();
    }

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

    void validateOneSignature(CBORMap csfContainer, CBORObject signedObject) {

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
    }

    /**
     * Validates signed CBOR object.
     * <p>
     * This method presumes that <code>signedObject</code> holds
     * an embedded signature according to CSF.
     * </p>
     * 
     * @param signedObject Signed CBOR object
     * @return The original <code>signedObject</code>
     */
    public CBORObject validate(CBORObject signedObject) {

        // There may be a tag holding the signed map.
        CBORMap signedMap = CBORCryptoUtils.unwrapContainerMap(signedObject,
                                                               tagPolicy,
                                                               tagCollector);

        // Fetch signature container object.
        // Need to separate single and multiple signatures.
        if (multiSignFlag) {
            CBORArray arrayOfSignatures = signedMap.get(CSF_CONTAINER_LBL).getArray();
            for (int i = 0; i < arrayOfSignatures.size(); i++) {
                CBORMap csfContainer = arrayOfSignatures.get(i).getMap();
                signedMap.update(CSF_CONTAINER_LBL, new CBORArray().add(csfContainer), true);
                validateOneSignature(csfContainer, signedObject);
            }
            signedMap.update(CSF_CONTAINER_LBL, arrayOfSignatures, true);
        } else {
            validateOneSignature(signedMap.get(CSF_CONTAINER_LBL).getMap(), signedObject);
        }
        
        // Return it as well.
        return signedObject;
    }
}
