/*
 *  Copyright 2006-2024 WebPKI.org (https://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.wasp;

import java.io.IOException;

import java.util.Date;

import org.webpki.crypto.SignerInterface;


public interface SignatureProfileResponseEncoder {
    void createSignedData(SignerInterface signer,
                          SignatureResponseEncoder s_resp_enc,
                          SignatureRequestDecoder s_req_dec,
                          String requestUrl,
                          Date clientTime,
                          byte[] server_certificate_fingerprint) throws IOException;
}
