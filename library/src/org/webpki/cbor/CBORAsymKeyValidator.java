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

import java.security.PublicKey;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CryptoException;
import org.webpki.crypto.SignatureWrapper;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Class for CBOR asymmetric key signature validation.
 *<p>
 * See {@link CBORValidator} for details.
 *</p> 
 */
public class CBORAsymKeyValidator extends CBORValidator {
    
    /**
     * Interface for dynamic key retrieval.
     */
    public interface KeyLocator {

        /**
         * Retrieves validation key and verifies meta data.
         * <p>
         * An implementation is supposed to throw an exception if it
         * does not find a matching key or if the supplied algorithm does
         * not meet the policy.
         * </p>
         * 
         * @param optionalPublicKey Optional public key found in the signature object
         * @param optionalKeyId KeyId or <code>null</code>
         * @param algorithm Signature algorithm
         * @return Validation key
         */
        PublicKey locate(PublicKey optionalPublicKey, 
                         CBORObject optionalKeyId, 
                         AsymSignatureAlgorithms algorithm);
    }
    
    KeyLocator keyLocator;

    /**
     * Initializes a validator with a public key.
     * <p>
     * This constructor presumes that the validation key is given by the context
     * and that the supplied algorithm meets the policy.
     * </p>
     * @see CBORAsymKeyValidator(KeyLocator)
     * @param publicKey The anticipated public key
     */
    public CBORAsymKeyValidator(PublicKey publicKey) {
        this((optionalPublicKey, optionalKeyId, algorithm) -> publicKey);
    }

    /**
     * Initializes a validator with a key locator.
     * <p>
     * This constructor provides full control for the verifier
     * regarding in-lined public keys and key identifiers.
     * </p>
     * <p>
     * If no public key is found in the signature object, 
     * the {@link KeyLocator} will be called BEFORE signature validation
     * with a <code>null</code> public key argument.  This permits
     * applications to retrieve a suitable key for validation.
     * This is usually done by requiring a key identifier.
     * </p>
     * <p>
     * If on the other a public is found in the signature object,
     * it will be used for signature validation.  AFTER successful
     * signature validation, the {@link KeyLocator} will be called
     * with the public key argument holding the public key of
     * the signature object.  This permits applications to first
     * validate the signature and then lookup the key which may
     * simplify database design. 
     * </p>
     * 
     * @param keyLocator KeyLocator implementation
     */
    public CBORAsymKeyValidator(KeyLocator keyLocator) {
        this.keyLocator = keyLocator;
    }

    @Override
    void coreValidation(CBORMap signatureObject, 
                        int coseAlgorithmId,
                        CBORObject optionalKeyId,
                        byte[] signatureValue,
                        byte[] signedData) {
        
        // Get signature algorithm.
        AsymSignatureAlgorithms algorithm =
                AsymSignatureAlgorithms.getAlgorithmFromId(coseAlgorithmId);
        
        // Fetch public key if there is one.
        PublicKey inLinePublicKey = null;
        if (signatureObject.hasKey(PUBLIC_KEY_LABEL)) {
            inLinePublicKey = CBORPublicKey.convert(signatureObject.getObject(PUBLIC_KEY_LABEL));
            // Please select ONE method for identifying the signature key.
            CBORCryptoUtils.rejectPossibleKeyId(optionalKeyId);
        }

        // If we have no in-line public key we need to call the key locator.
        PublicKey publicKey = inLinePublicKey == null ?
                 keyLocator.locate(null, optionalKeyId, algorithm) : inLinePublicKey;
        
        // Now we have everything needed for validating the signature.
        SignatureWrapper.validate(publicKey,
                                  algorithm, 
                                  signedData, 
                                  signatureValue,
                                  null);

        // If we have an in-line public key, check that it matches the expected one.
        if (inLinePublicKey != null && 
            !inLinePublicKey.equals(keyLocator.locate(inLinePublicKey, 
                                                      optionalKeyId, 
                                                      algorithm))) {
            throw new CryptoException("Public keys not identical");
        }
    }
}
