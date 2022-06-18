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

import java.security.cert.X509Certificate;

import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.KeyEncryptionAlgorithms;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Class for creating CBOR X509 encryptions.
 * 

 */
public class CBORX509Encrypter extends CBOREncrypter {

    KeyEncryptionAlgorithms keyEncryptionAlgorithm;

    X509Certificate[] certificatePath;
    
    /**
     * Initializes an encrypter object.
     * 
     * @param certificatePath The certificate path to encrypt with
     * @param keyEncryptionAlgorithm KEK algorithm
     * @param contentEncryptionAlgorithm Actual encryption algorithm
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public CBORX509Encrypter(X509Certificate[] certificatePath,
                             KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                             ContentEncryptionAlgorithms contentEncryptionAlgorithm) 
            throws IOException, GeneralSecurityException {
        super(contentEncryptionAlgorithm);
        this.certificatePath = certificatePath;
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
    }

    @Override
    byte[] getContentEncryptionKey(CBORMap keyEncryption)
            throws IOException, GeneralSecurityException {
        
        // X509 encryptions mandate a certificate path.
        keyEncryption.setObject(CERT_PATH_LABEL, 
                                CBORCryptoUtils.encodeCertificateArray(certificatePath));

        // Key IDs are not permitted.
        CBORCryptoUtils.checkKeyId(optionalKeyId);
         
        // Create common key encryption data and return content encryption key. 
        return CBORCryptoUtils.setupBasicKeyEncryption(certificatePath[0].getPublicKey(),
                                                       keyEncryption,
                                                       keyEncryptionAlgorithm,
                                                       contentEncryptionAlgorithm);
    }
    
    @Override
    CBORMap getEncryptionObject(CBORMap original) throws IOException {
        CBORMap keyEncryption = new CBORMap();
        original.setObject(KEY_ENCRYPTION_LABEL, keyEncryption);
        return keyEncryption;
    }
}
