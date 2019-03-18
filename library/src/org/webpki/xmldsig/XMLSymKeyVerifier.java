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

import java.security.GeneralSecurityException;

import org.webpki.crypto.SymKeyVerifierInterface;


public class XMLSymKeyVerifier extends XMLVerifierCore {

    SymKeyVerifierInterface sym_verifier;

    void verify(XMLSignatureWrapper signature) throws IOException, GeneralSecurityException {
        // Right kind of XML Dsig?
        if (signature.publicKey != null || signature.certificates != null) {
            throw new IOException("Missing symmetric key!");
        }

        // Check signature
        core_verify(signature, null);
    }


    public XMLSymKeyVerifier(SymKeyVerifierInterface sym_verifier) {
        this.sym_verifier = sym_verifier;
    }

}
