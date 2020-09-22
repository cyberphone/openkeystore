/*
 *  Copyright 2018-2020 WebPKI.org (http://webpki.org).
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
package org.webpki.jose;

import java.io.IOException;

import org.webpki.crypto.AlgorithmPreferences;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;

/**
 * Core JWS encoder
 */
public class JwsEncoder {
    
    JSONObjectWriter jwsProtectedHeader;
    
    JOSESupport.KeyHolder keyHolder;

    /**
     * JWS signature encoder
     * @param keyHolder Holds JWS signature key and algorithm
     * @throws IOException
     */
    public JwsEncoder(JOSESupport.KeyHolder keyHolder) throws IOException {
        jwsProtectedHeader = new JSONObjectWriter()
            .setString(JOSESupport.ALG_JSON, 
                       keyHolder.signatureAlgorithm.isOkp() ? 
                    JOSESupport.EdDSA 
                                                                : 
                    keyHolder.signatureAlgorithm.getAlgorithmId(AlgorithmPreferences.JOSE));
        this.keyHolder = keyHolder;
    }

    /**
     * Add header elements
     * @param items
     * @throws IOException
     */
    public void addHeaderItems(JSONObjectReader items) throws IOException {
        for (String key : items.getProperties()) {
            jwsProtectedHeader.copyElement(key, key, items);
        }
    }
}
