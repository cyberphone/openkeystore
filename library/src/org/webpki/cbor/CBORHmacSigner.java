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

/**
 * Class for creating CBOR HMAC signatures.
 * 
 * Note that signer objects may be used any number of times
 * (assuming that the same parameters are valid).  They are also
 * thread-safe.
 */
public class CBORHmacSigner extends CBORSigner {

    byte[] secretKey;

    HmacAlgorithms hmacAlgorithm;

    /**
     * Initialize signer.
     * 
     * @param secretKey The key to sign with
     * @param hmacAlgorithm The algorithm to use
     * @throws IOException 
     */
    public CBORHmacSigner(byte[] secretKey, HmacAlgorithms hmacAlgorithm) throws IOException {
        this.secretKey = secretKey;
        this.hmacAlgorithm = hmacAlgorithm;
        this.cborAlgorithmId = WEBPKI_2_CBOR_ALG.get(hmacAlgorithm);
    }
    
    @Override
    byte[] signData(byte[] dataToBeSigned) throws GeneralSecurityException, IOException {
        return hmacAlgorithm.digest(secretKey, dataToBeSigned);
    }
}
