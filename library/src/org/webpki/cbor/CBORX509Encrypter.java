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
package org.webpki.cbor;

import java.security.cert.X509Certificate;

import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.KeyEncryptionAlgorithms;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Class for X.509 encryption.
 */
public class CBORX509Encrypter extends CBOREncrypter<CBORX509Encrypter> {

    KeyEncryptionAlgorithms keyEncryptionAlgorithm;

    X509Certificate[] certificatePath;
    
    /**
     * Creates an encrypter object.
     * 
     * @param certificatePath Encryption certificate path
     * @param keyEncryptionAlgorithm Key encryption algorithm
     * @param contentEncryptionAlgorithm Content encryption algorithm
     */
    public CBORX509Encrypter(X509Certificate[] certificatePath,
                             KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                             ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
        super(contentEncryptionAlgorithm);
        this.certificatePath = certificatePath;
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
    }

    @Override
    byte[] getContentEncryptionKey(CBORMap keyEncryption) {
        
        // X.509 encryptions mandate a certificate path.
        keyEncryption.set(CXF_CERT_PATH_LBL, 
                          CBORCryptoUtils.encodeCertificateArray(certificatePath));

        // Key IDs are not permitted.
        CBORCryptoUtils.rejectPossibleKeyId(optionalKeyId);
         
        // Create common key encryption data and return content encryption key. 
        return CBORCryptoUtils.commonKeyEncryption(certificatePath[0].getPublicKey(),
                                                   keyEncryption,
                                                   keyEncryptionAlgorithm,
                                                   contentEncryptionAlgorithm);
    }

    @Override
    CBORX509Encrypter getThis() {
        return this;
    }
}
