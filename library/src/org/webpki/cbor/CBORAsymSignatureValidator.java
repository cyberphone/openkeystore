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

/**
 * Class for CBOR asymmetric key signature validation
 * 
 * Note that a validator object may be used any number of times
 * (assuming that the same parameters are valid).  It is also
 * thread-safe. 
 */
public class CBORAsymSignatureValidator extends CBORValidator {
    
    public interface KeyLocator {

        PublicKey locate(PublicKey optionalPublicKey, 
                         String optionalKeyId, 
                         AsymSignatureAlgorithms signatureAlgorithm)
            throws IOException, GeneralSecurityException;
    }
    
    PublicKey publicKey;
    KeyLocator keyLocator;

    /**
     * Initialize validator with public key.
     * 
     * @param publicKey The anticipated public key
     */
    public CBORAsymSignatureValidator(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * Initialize validator with a locator.
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
    public CBORAsymSignatureValidator(KeyLocator keyLocator) {
        this.keyLocator = keyLocator;
    }

    @Override
    void validate(CBORIntegerMap signatureObject, 
                  int coseSignatureAlgorithm,
                  String optionalKeyId,
                  byte[] signatureValue,
                  byte[] signedData) throws IOException, GeneralSecurityException {
        AsymSignatureAlgorithms signatureAlgorithm =
                (AsymSignatureAlgorithms) CBORSigner.getSignatureAlgorithm(
                        coseSignatureAlgorithm, true);
        PublicKey inLinePublicKey = null;
        if (signatureObject.hasKey(CBORSigner.PUBLIC_KEY_LABEL)) {
            inLinePublicKey = CBORPublicKey.decodePublicKey(
                    signatureObject.getObject(CBORSigner.PUBLIC_KEY_LABEL));
        }
        if (keyLocator != null) {
            publicKey = inLinePublicKey == null ?
                 keyLocator.locate(inLinePublicKey, optionalKeyId, signatureAlgorithm) 
                                                : 
                 inLinePublicKey;
        }
        if (inLinePublicKey != null) {
            if (!publicKey.equals(inLinePublicKey)) {
                throw new GeneralSecurityException("Public keys not identical");
            }
        }
        KeyAlgorithms keyAlgorithm = KeyAlgorithms.getKeyAlgorithm(publicKey);
        if (signatureAlgorithm.getKeyType() != keyAlgorithm.getKeyType()) {
            throw new IllegalArgumentException("Algorithm " + signatureAlgorithm + 
                                  " does not match key type " + keyAlgorithm);
        }
        if (!new SignatureWrapper(signatureAlgorithm, publicKey)
                 .update(signedData)
                 .verify(signatureValue)) {
            throw new GeneralSecurityException("Bad signature for key: " + publicKey.toString());
        }
        if (keyLocator != null && inLinePublicKey != null) {
            keyLocator.locate(inLinePublicKey, optionalKeyId, signatureAlgorithm);
        }
    }
}
