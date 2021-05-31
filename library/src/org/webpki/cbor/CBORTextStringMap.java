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

    /**
     * Create a CBOR map <code>{}</code> with text string keys.
     */
    public CBORTextStringMap() {}

    @Override
    public CBORTypes getType() {
        return CBORTypes.TEXT_STRING_MAP;
    }
 
    /**
     * Remove object from map.
     * 
     * @param key Key in string format
     * @return The CBORTextStringMap
     * @throws IOException
     */
    public CBORTextStringMap removeObject(String key) throws IOException {
        removeObject(new CBORTextString(key));
        return this;
    }
    
    /**
     * Set map value.
     * 
     * @param key Key in string format
     * @param value Value in CBOR notation
     * @return The CBORIntegerMap
     * @throws IOException
     */
    public CBORTextStringMap setObject(String key, CBORObject value) throws IOException {
        setObject(new CBORTextString(key), value);
        return this;
    }

    /**
     * Validate signed CBOR object.
     * 
     * @param key Of map to validate
     * @param validator Holds the validation method
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public void validate(String key, CBORValidator validator) throws IOException, 
                                                                     GeneralSecurityException {
        validate(new CBORTextString(key), validator);
    }

    /**
     * Sign CBOR object.
     * 
     * @param key Of the map to sign
     * @param signer Holder of signature method and key
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public CBORTextStringMap sign(String key, CBORSigner signer) 
            throws IOException, GeneralSecurityException {
        sign(new CBORTextString(key), signer);
        return this;
    }

    /**
     * Check map for key presence.
     * 
     * @param key Key in string format
     * @return <code>true</code> if the key is present
     */
    public boolean hasKey(String key) {
        return hasKey(new CBORTextString(key));
    }

    /**
     * Get map value.
     * 
     * @param key Key in string format
     * @return Value in CBOR notation
     * @throws IOException
     */
    public CBORObject getObject(String key) throws IOException {
        return getObject(new CBORTextString(key));
    }
}
