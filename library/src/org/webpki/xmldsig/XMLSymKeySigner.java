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
import java.security.PublicKey;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.SymKeySignerInterface;


public class XMLSymKeySigner extends XMLSignerCore {

    SymKeySignerInterface sym_signer;

    String key_name = "symmetric-key";

    PublicKey populateKeys(XMLSignatureWrapper r) throws GeneralSecurityException, IOException {
        return null;
    }

    byte[] getSignatureBlob(byte[] data, AsymSignatureAlgorithms sig_alg) throws GeneralSecurityException, IOException {
        return sym_signer.signData(data, sym_signer.getMacAlgorithm());
    }


    /**
     * Creates an XMLSymKeySigner.
     *
     * @param signer Signer interface
     */
    public XMLSymKeySigner(SymKeySignerInterface signer) {
        this.sym_signer = signer;
    }

    public void SetKeyName(String key_name) {
        this.key_name = key_name;
    }

}
