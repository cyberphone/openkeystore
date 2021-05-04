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

/**
 * Class for CBOR asymmetric key signature validation
 * 
 * Note that a validator object may be used any number of times
 * (assuming that the same parameters are valid).  It is also
 * thread-safe. 
 */
public class CBORAsymSignatureValidator extends CBORValidator {
    
    PublicKey publicKey;

    /**
     * Initialize validator with public key.
     * 
     * @param publicKey The anticipated public key
     */
    public CBORAsymSignatureValidator(PublicKey publicKey) {
        this.publicKey = publicKey;
    }
    
    /**
     * Initialize validator without public key.
     * 
     * This option requires that the public key is provided in
     * the signature object.
     */
    public CBORAsymSignatureValidator() {
    }
    
    @Override
    void validate(CBORIntegerMap signatureObject, 
                  int signatureAlgorithm, 
                  byte[] signedData) {
        if (signatureObject.hasKey(CBORSigner.PUBLIC_KEY_LABEL)) {
            
        }
        if (publicKey == null) {
            
        }
        // TODO Auto-generated method stub
        
    }
}
