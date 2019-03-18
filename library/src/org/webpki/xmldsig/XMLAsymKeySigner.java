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

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.AsymKeySignerInterface;


public class XMLAsymKeySigner extends XMLSignerCore {

    AsymKeySignerInterface signer_impl;

    PublicKey populateKeys(XMLSignatureWrapper r) throws IOException {
        return r.publicKey = signer_impl.getPublicKey();
    }

    byte[] getSignatureBlob(byte[] data, AsymSignatureAlgorithms sig_alg) throws IOException {
        return signer_impl.signData(data, sig_alg);
    }


    /**
     * Creates an XMLAsymKeySigner.
     *
     * @param signer Signer implementation
     */
    public XMLAsymKeySigner(AsymKeySignerInterface signer) {
        this.signer_impl = signer;
    }
}
