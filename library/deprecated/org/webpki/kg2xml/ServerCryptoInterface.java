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
package org.webpki.kg2xml;

import java.io.IOException;
import java.io.Serializable;

import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;

import org.webpki.crypto.KeyAlgorithms;

public interface ServerCryptoInterface extends Serializable
  {
    ECPublicKey generateEphemeralKey (KeyAlgorithms ec_key_algorithm) throws IOException;
    
    void generateAndVerifySessionKey (ECPublicKey client_ephemeral_key,
                                      byte[] kdf_data,
                                      byte[] attestation_arguments,
                                      X509Certificate device_certificate,
                                      byte[] session_attestation) throws IOException;

    public byte[] mac (byte[] data, byte[] key_modifier) throws IOException;
    
    public byte[] encrypt (byte[] data) throws IOException;

    public byte[] generateNonce () throws IOException;

    public byte[] generateKeyManagementAuthorization (PublicKey keyManagementKey, byte[] data) throws IOException;
    
    public PublicKey[] enumerateKeyManagementKeys () throws IOException;
  }
