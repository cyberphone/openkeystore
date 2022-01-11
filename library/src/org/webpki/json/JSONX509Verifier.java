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

import org.webpki.crypto.X509VerifierInterface;

/**
 * Initiator object for X.509 signature verifiers.
 */
public class JSONX509Verifier extends JSONVerifier {

    X509VerifierInterface verifier;

    /**
     * Verifier for X509-based keys.
     * Note that you can also access the received X509 key from {@link JSONSignatureDecoder}.
     *
     * @param verifier Verifier which presumably would do full PKIX path validation etc.
     */
    public JSONX509Verifier(X509VerifierInterface verifier) {
        super(JSONSignatureTypes.X509_CERTIFICATE);
        this.verifier = verifier;
    }

    @Override
    void verify(JSONSignatureDecoder signatureDecoder) throws IOException,
                                                              GeneralSecurityException {
        verifier.verifyCertificatePath(signatureDecoder.certificatePath);
    }
}
