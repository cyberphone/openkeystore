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

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
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
     * For dynamic key retrieval.
     */
    public interface KeyLocator {

        /**
         * Checks signature data and retrieves validation key.
         * 
         * @param optionalPublicKey Optional public key found in the signature object
         * @param optionalKeyId KeyId or <code>null</code>
         * @param signatureAlgorithm The specified signature algorithm
         * @return Public key for signature validation
         * @throws IOException
         * @throws GeneralSecurityException
         */
        PublicKey locate(PublicKey optionalPublicKey, 
                         CBORObject optionalKeyId, 
                         AsymSignatureAlgorithms signatureAlgorithm)
            throws IOException, GeneralSecurityException;
    }
    
    KeyLocator keyLocator;

    /**
     * Initializes a validator with a public key.
     * 
     * @param publicKey The anticipated public key
     */
    public CBORAsymKeyValidator(PublicKey publicKey) {
        this(new KeyLocator() {

            @Override
            public PublicKey locate(PublicKey optionalPublicKey,
                                    CBORObject optionalKeyId,
                                    AsymSignatureAlgorithms signatureAlgorithm)
                    throws IOException, GeneralSecurityException {
                return publicKey;
            }
            
        });
    }

    /**
     * Initializes a validator with a key locator.
     * 
     * This option provides full control for the verifier
     * regarding in-lined public keys and key identifiers.
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
     * @param keyLocator The call back
     */
    public CBORAsymKeyValidator(KeyLocator keyLocator) {
        this.keyLocator = keyLocator;
    }

    static void asymKeySignatureValidation(PublicKey publicKey,
                                           AsymSignatureAlgorithms signatureAlgorithm,
                                           byte[] signedData,
                                           byte[] signatureValue) 
            throws GeneralSecurityException, IOException {

        // Verify that the public key matches the signature algorithm.
        KeyAlgorithms keyAlgorithm = KeyAlgorithms.getKeyAlgorithm(publicKey);
        if (signatureAlgorithm.getKeyType() != keyAlgorithm.getKeyType()) {
            throw new GeneralSecurityException("Algorithm " + signatureAlgorithm + 
                                  " does not match key type " + keyAlgorithm);
        }
        
        // Finally, verify the signature.
        if (!new SignatureWrapper(signatureAlgorithm, publicKey)
                 .update(signedData)
                 .verify(signatureValue)) {
            throw new GeneralSecurityException("Bad signature for key: " + publicKey.toString());
        }
    }

    @Override
    void coreValidation(CBORMap signatureObject, 
                        int coseAlgorithmId,
                        CBORObject optionalKeyId,
                        byte[] signatureValue,
                        byte[] signedData) throws IOException, GeneralSecurityException {
        
        // Get signature algorithm.
        AsymSignatureAlgorithms signatureAlgorithm =
                AsymSignatureAlgorithms.getAlgorithmFromId(coseAlgorithmId);
        
        // Fetch public key if there is one.
        PublicKey inLinePublicKey = null;
        if (signatureObject.hasKey(PUBLIC_KEY_LABEL)) {
            CBORCryptoUtils.checkKeyId(optionalKeyId);
            inLinePublicKey = CBORPublicKey.decode(signatureObject.getObject(PUBLIC_KEY_LABEL));
        }

        // If we have no in-line public key we need to call the key locator.
        PublicKey publicKey = inLinePublicKey == null ?
                 keyLocator.locate(null, optionalKeyId, signatureAlgorithm) : inLinePublicKey;
        
        // Now we have everything needed for validating the signature.
        asymKeySignatureValidation(publicKey, signatureAlgorithm, signedData, signatureValue);

        // If we have an in-line public key, check that it matches the expected one.
        if (inLinePublicKey != null && 
            !inLinePublicKey.equals(keyLocator.locate(inLinePublicKey, 
                                                      optionalKeyId, 
                                                      signatureAlgorithm))) {
            throw new GeneralSecurityException("Public keys not identical");
        }
    }
}
