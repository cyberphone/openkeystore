/*
 *  Copyright 2006-2018 WebPKI.org (http://webpki.org).
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
package org.webpki.xmldsig;

import java.io.IOException;

import java.security.PublicKey;
import java.security.GeneralSecurityException;


public class XMLAsymKeyVerifier extends XMLVerifierCore {

    private PublicKey publicKey;

    public PublicKey getPublicKey() {
        return publicKey;
    }


    void verify(XMLSignatureWrapper signature) throws IOException, GeneralSecurityException {
        // Right kind of XML Dsig?
        if ((publicKey = signature.publicKey) == null) {
            throw new IOException("Missing public key!");
        }

        // Check signature
        core_verify(signature, publicKey);
    }

}
