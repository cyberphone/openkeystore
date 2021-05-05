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
package org.webpki.cbor;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Class for holding CBOR text string maps.
 */
public class CBORTextStringMap extends CBORMapBase {

    public CBORTextStringMap() {}

    public CBORTextStringMap setMappedValue(String key, CBORObject value) throws IOException {
        setObject(new CBORTextString(key), value);
        return this;
    }

    public CBORValidator validate(String key, CBORValidator validator) 
            throws IOException, GeneralSecurityException {
        return validate(new CBORTextString(key), validator);
    }

    public CBORTextStringMap sign(String key, CBORSigner signer) 
            throws IOException, GeneralSecurityException {
        sign(new CBORTextString(key), signer);
        return this;
    }

    public boolean hasKey(String key) {
        return hasKey(new CBORTextString(key));
    }

    public CBORObject getMappedValue(String key) throws IOException {
        return getObject(new CBORTextString(key));
    }
}
