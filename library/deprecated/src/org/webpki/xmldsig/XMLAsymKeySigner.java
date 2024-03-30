/*
 *  Copyright 2006-2024 WebPKI.org (https://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://apache.org/licenses/LICENSE-2.0
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
import java.security.PublicKey;

import org.webpki.crypto.AsymKeySignerInterface;


public class XMLAsymKeySigner extends XMLSignerCore {

    AsymKeySignerInterface signer_impl;
    PublicKey publicKey;

    PublicKey populateKeys(XMLSignatureWrapper r) throws IOException {
        return r.publicKey = publicKey;
    }

    byte[] getSignatureBlob(byte[] data)
            throws IOException, GeneralSecurityException {
        return signer_impl.signData(data);
    }


    /**
     * Creates an XMLAsymKeySigner.
     *
     * @param signer Signer implementation
     */
    public XMLAsymKeySigner(AsymKeySignerInterface signer, PublicKey publicKey) {
        this.signer_impl = signer;
        this.publicKey = publicKey;
    }
}
