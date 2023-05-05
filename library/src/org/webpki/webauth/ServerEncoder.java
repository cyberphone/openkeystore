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
package org.webpki.webauth;

import org.webpki.crypto.CryptoException;
import org.webpki.crypto.X509SignerInterface;

import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONX509Signer;

abstract class ServerEncoder extends JSONEncoder {

    abstract void writeServerRequest(JSONObjectWriter wr);

    final void bad(String message) {
        throw new CryptoException(message);
    }

    @Override
    public final String getContext() {
        return WebAuthConstants.WEBAUTH_NS;
    }

    @Override
    final protected void writeJSONData(JSONObjectWriter wr) {
        writeServerRequest(wr);

        ////////////////////////////////////////////////////////////////////////
        // Optional signature
        ////////////////////////////////////////////////////////////////////////
        if (signer != null) {
            wr.setSignature(new JSONX509Signer(signer));
        }
    }

    private X509SignerInterface signer;

    public void setRequestSigner(X509SignerInterface signer) {
        this.signer = signer;
    }
}
