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
package org.webpki.keygen2;

import java.io.IOException;

import org.webpki.crypto.VerifierInterface;

import org.webpki.json.JSONCryptoHelper;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONSignatureDecoder;
import org.webpki.json.JSONX509Verifier;

abstract class ClientDecoder extends KeyGen2Validator {

    private static final long serialVersionUID = 1L;

    private JSONSignatureDecoder signature;  // Optional

    abstract void readServerRequest(JSONObjectReader rd) throws IOException;

    public void verifySignature(VerifierInterface verifier) throws IOException {
        signature.verify(new JSONX509Verifier(verifier));
    }

    public boolean isSigned() {
        return signature != null;
    }

    @Override
    final protected void readJSONData(JSONObjectReader rd) throws IOException {
        readServerRequest(rd);

        //////////////////////////////////////////////////////////////////
        // Must be a Signature otherwise something has gone wrong...
        //////////////////////////////////////////////////////////////////
        if (rd.hasProperty(JSONObjectWriter.SIGNATURE_DEFAULT_LABEL_JSON)) {
            signature = rd.getSignature(new JSONCryptoHelper.Options());
        }
    }
}
