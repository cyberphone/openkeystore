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
package org.webpki.json;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import org.webpki.crypto.KeyAlgorithms;

/**
 * Initiator object for asymmetric key signature verifiers.
 */
public class JSONAsymKeyVerifier extends JSONVerifier {

    PublicKey expectedPublicKey;

    /**
     * Verifier for asymmetric keys.
     * Note that you can access the received public key from {@link JSONSignatureDecoder}
     * which is useful if there are multiple keys possible.
     *
     * @param expectedPublicKey Expected public key
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public JSONAsymKeyVerifier(PublicKey expectedPublicKey) 
    throws GeneralSecurityException, IOException {
        super(JSONSignatureTypes.ASYMMETRIC_KEY);
        this.expectedPublicKey = KeyAlgorithms.normalizePublicKey(expectedPublicKey);
    }

    @Override
    void verify(JSONSignatureDecoder signatureDecoder) 
            throws IOException, GeneralSecurityException {
        if (signatureDecoder.publicKey == null) {
            signatureDecoder.asymKeySignatureValidation(expectedPublicKey);
        } else if (!signatureDecoder.publicKey.equals(expectedPublicKey)) {
            throw new IOException("Provided public key differs from the signature key");
        }
    }
}
