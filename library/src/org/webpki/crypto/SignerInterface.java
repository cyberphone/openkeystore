/*
 *  Copyright 2006-2020 WebPKI.org (http://webpki.org).
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

import java.security.cert.X509Certificate;


/**
 * PKI signature interface.
 * Note that the actual key, certificate path, and signature creation mechanism are supposed to
 * be hosted by the implementing class.
 */
public interface SignerInterface {
    /**
     * @return Returns the certificate path associated with the key.
     * @throws IOException For various problems...
     */
    public X509Certificate[] getCertificatePath() throws IOException;

    /**
     * Signs data using the key.
     *
     * @param data      Data to be signed
     * @param algorithm Algorithm to use
     * @return Signed data
     * @throws IOException For various problems...
     */
    public byte[] signData(byte[] data, AsymSignatureAlgorithms algorithm) throws IOException;
}
