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
import java.security.PrivateKey;

import java.security.cert.X509Certificate;

import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.KeyEncryptionAlgorithms;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Class for X509 decryption.
 */
public class CBORX509Decrypter extends CBORDecrypter {
    
    /**
     * Interface for dynamic key retrieval.
     */
    public interface KeyLocator {

        /**
         * Lookup of private decryption key.

         * This interface also enables encryption parameter validation.
         * 
         * @param certificatePath Certificate path in the encryption object
         * @param keyEncryptionAlgorithm The requested key encryption algorithm
         * @param contentEncryptionAlgorithm The requested content encryption algorithm
         * @return Decryption key
         * @throws IOException
         * @throws GeneralSecurityException
         */
        PrivateKey locate(X509Certificate[] certificatePath,
                          KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                          ContentEncryptionAlgorithms contentEncryptionAlgorithm)
            throws IOException, GeneralSecurityException;
    }
    
    KeyLocator keyLocator;
    
   /**
     * Initializes a decrypter with a key locator.
     * 
     * @param keyLocator KeyLocator implementation
     */
    public CBORX509Decrypter(KeyLocator keyLocator) {
        this.keyLocator = keyLocator;
    }
    
    @Override
    byte[] getContentEncryptionKey(CBORMap innerObject,
                                   ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                                   CBORObject optionalKeyId) throws IOException,
                                                                    GeneralSecurityException {
        // keyId and certificates? Never!
        CBORCryptoUtils.rejectPossibleKeyId(optionalKeyId);

        // Mandatory algorithm
        KeyEncryptionAlgorithms keyEncryptionAlgorithm =
                KeyEncryptionAlgorithms.getAlgorithmFromId(
                        innerObject.getObject(ALGORITHM_LABEL).getInt());
 
        // Fetch certificate path
        X509Certificate[] certificatePath = CBORCryptoUtils.decodeCertificateArray(
                innerObject.getObject(CERT_PATH_LABEL).getArray());

        // Now we have what it takes for finding the proper private key
        PrivateKey privateKey = keyLocator.locate(certificatePath,
                                                  keyEncryptionAlgorithm,
                                                  contentEncryptionAlgorithm);
        return CBORCryptoUtils.asymKeyDecrypt(privateKey,
                                              innerObject,
                                              keyEncryptionAlgorithm,
                                              contentEncryptionAlgorithm); 
    }
}
