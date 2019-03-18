/*
 *  Copyright 2006-2019 WebPKI.org (http://webpki.org).
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
package org.webpki.jose;

import java.io.IOException;

import org.webpki.crypto.MACAlgorithms;

import org.webpki.util.ArrayUtil;

public class JOSEHmacValidator implements JOSESupport.CoreSignatureValidator {
    
    byte[] hmacKey;
    MACAlgorithms algorithm;
    
    public JOSEHmacValidator(byte[] hmacKey, MACAlgorithms algorithm) {
        this.hmacKey = hmacKey;
        this.algorithm = algorithm;
    }

    @Override
    public void validate(byte[] signedData, byte[] JWS_Signature) throws IOException {
        if (!ArrayUtil.compare(algorithm.digest(hmacKey, 
                                                signedData),
                               JWS_Signature)) {
            throw new IOException("HMAC signature validation error");
        }
    }

}
