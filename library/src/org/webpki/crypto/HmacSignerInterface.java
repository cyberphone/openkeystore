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
package org.webpki.crypto;


import java.io.IOException;

import java.security.GeneralSecurityException;

/**
 * Common interface for HMAC signatures.
 *
 */
public interface HmacSignerInterface {

    /**
     * Sign data.
     * 
     * @param data Data to sign
     * @return Signed data
     * @throws IOException
     * @throws GeneralSecurityException
     */
    byte[] signData(byte[] data) throws IOException, GeneralSecurityException;

    /**
     * Get signature algorithm.
     * 
     * @return Signature algorithm
     * @throws IOException
     * @throws GeneralSecurityException
     */
    default HmacAlgorithms getAlgorithm() throws IOException, GeneralSecurityException {
        throw new GeneralSecurityException("Missing implementation!");
    }

    /**
     * Set signature algorithm.
     * 
     * @param algorithm The signature algorithm
     * @throws IOException
     * @throws GeneralSecurityException
     */
    default void setAlgorithm(HmacAlgorithms algorithm) throws IOException,
                                                               GeneralSecurityException {
        throw new GeneralSecurityException("Missing implementation!");
    }

}
