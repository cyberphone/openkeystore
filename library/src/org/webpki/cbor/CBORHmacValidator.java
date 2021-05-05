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

import org.webpki.crypto.HmacAlgorithms;
import org.webpki.util.ArrayUtil;

/**
 * Class for CBOR HMAC signature validation.
 * 
 * Note that validator objects may be used any number of times
 * (assuming that the same parameters are valid).  They are also
 * thread-safe. 
 */
public class CBORHmacValidator extends CBORValidator {
    
    public interface KeyLocator {

        byte[] locate(String optionalKeyId, HmacAlgorithms hmacAlgorithm)
            throws IOException, GeneralSecurityException;
    }
    
    byte[] secretKey;
    KeyLocator keyLocator;

    /**
     * Initialize validator with public key.
     * 
     * @param secretKey The anticipated public key
     */
    public CBORHmacValidator(byte[] secretKey) {
        this.secretKey = secretKey;
    }

    /**
     * Initialize validator with a locator.
     * 
     * This option provides full control for the verifier
     * regarding key identifiers.
     *
     * @param keyLocator The call back
     */
    public CBORHmacValidator(KeyLocator keyLocator) {
        this.keyLocator = keyLocator;
    }

    @Override
    void validate(CBORIntegerMap signatureObject, 
                  int coseSignatureAlgorithm,
                  String optionalKeyId,
                  byte[] signatureValue,
                  byte[] signedData) throws IOException, GeneralSecurityException {
        // Get algorithm from the signature object.
        HmacAlgorithms hmacAlgorithm =
                (HmacAlgorithms) CBORSigner.getSignatureAlgorithm(coseSignatureAlgorithm, false);

        // If there is a locator, call it.
        if (keyLocator != null) {
            secretKey = keyLocator.locate(optionalKeyId, hmacAlgorithm);
        }

        // Finally, verify the HMAC.
        if (!ArrayUtil.compare(hmacAlgorithm.digest(secretKey, signedData), signatureValue)) {
             throw new GeneralSecurityException("HMAC signature validation error");
        }
    }
}
