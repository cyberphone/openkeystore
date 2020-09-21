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

import org.webpki.crypto.MACAlgorithms;

/**
 * Holder of JWS HMAC key and algorithm
 */
public class SymKeyHolder extends JOSESupport.CoreKeyHolder {
    
    /**
     * Create holder
     * @param secretKey
     * @param macAlgorithms
     */
    public SymKeyHolder(byte[] secretKey, MACAlgorithms macAlgorithms) {
        super(secretKey, macAlgorithms);
    }

}
