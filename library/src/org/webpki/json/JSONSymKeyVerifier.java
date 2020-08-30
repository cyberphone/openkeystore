/*
 *  Copyright 2006-2020 WebPKI.org (http://webpki.org).
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
package org.webpki.json;

import java.io.IOException;

import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SymKeyVerifierInterface;

import org.webpki.util.ArrayUtil;

/**
 * Initiator object for symmetric key signature verifiers.
 */
public class JSONSymKeyVerifier extends JSONVerifier {

    private static final long serialVersionUID = 1L;

    SymKeyVerifierInterface verifier;

    /**
     * Custom crypto verifier for symmetric keys.
     * Note that you can access the received KeyIi from {@link JSONSignatureDecoder}.
     *
     * @param verifier Handle to implementation
     */
    public JSONSymKeyVerifier(SymKeyVerifierInterface verifier) {
        super(JSONSignatureTypes.SYMMETRIC_KEY);
        this.verifier = verifier;
    }

    /**
     * JCE based verifier for symmetric keys.
     * Note that you can access the received KeyId from {@link JSONSignatureDecoder}.
     *
     * @param rawKey Key
     */
    public JSONSymKeyVerifier(final byte[] rawKey) {
        this(new SymKeyVerifierInterface() {

            @Override
            public boolean verifyData(byte[] data,
                                      byte[] digest,
                                      MACAlgorithms algorithm,
                                      String keyId) throws IOException {
                return ArrayUtil.compare(digest, algorithm.digest(rawKey, data));
            }
            
        });
    }

    @Override
    void verify(JSONSignatureDecoder signatureDecoder) throws IOException {
        if (!verifier.verifyData(signatureDecoder.normalizedData,
                                 signatureDecoder.signatureValue,
                                 (MACAlgorithms) signatureDecoder.signatureAlgorithm,
                                 signatureDecoder.keyId)) {
            throw new IOException("Bad signature for key: " + signatureDecoder.keyId);
        }
    }
}
