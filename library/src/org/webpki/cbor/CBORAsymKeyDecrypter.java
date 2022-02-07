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
import java.security.PublicKey;

import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.EncryptionCore;
import org.webpki.crypto.KeyEncryptionAlgorithms;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Class for CBOR asymmetric key decryption.
 * 
 * It uses COSE algorithms but relies on CEF for the packaging.
 * 
 * Note that decrypter objects may be used any number of times
 * (assuming that the same parameters are valid).  They are also
 * thread-safe. 
 */
public class CBORAsymKeyDecrypter extends CBORDecrypter {
    
    /**
     * For dynamic key retrieval.
     */
    public interface KeyLocator {

        /**
         * Lookup of private decryption key.

         * This interface also enables encryption parameter validation.
         * 
         * @param optionalPublicKey Optional public key found in the encryption object
         * @param optionalKeyId Optional key Id found in the encryption object
         * @param contentEncryptionAlgorithm The requested content encryption algorithm
         * @param keyEncryptionAlgorithm The requested key encryption algorithm
         * @return Private key for decryption
         * @throws IOException
         * @throws GeneralSecurityException
         */
        PrivateKey locate(PublicKey optionalPublicKey, 
                          CBORObject optionalKeyId,
                          ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                          KeyEncryptionAlgorithms keyEncryptionAlgorithm)
            throws IOException, GeneralSecurityException;
    }
    
    KeyLocator keyLocator;
    
    /**
     * Initializes a decrypter with a private key.
     * 
     * @param privateKey The anticipated private key to decrypt with
     */
    public CBORAsymKeyDecrypter(PrivateKey privateKey) {
        this(new KeyLocator() {

            @Override
            public PrivateKey locate(PublicKey optionalPublicKey,
                                     CBORObject optionalKeyId,
                                     ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                                     KeyEncryptionAlgorithms keyEncryptionAlgorithm)
                    throws IOException, GeneralSecurityException {
                return privateKey;
            }
            
        });
    }

    /**
     * Initializes a decrypter with a key locator.
     * 
     * @param keyLocator The call back
     */
    public CBORAsymKeyDecrypter(KeyLocator keyLocator) {
        this.keyLocator = keyLocator;
    }
    
    @Override
    CBORMap getOptionalKeyEncryptionObject(CBORMap encryptionObject) throws IOException {
        return encryptionObject.getObject(KEY_ENCRYPTION_LABEL).getMap(); 
     }
 
    @Override
    byte[] getContentEncryptionKey(CBORMap innerObject,
                                   ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                                   CBORObject optionalKeyId) throws IOException,
                                                                    GeneralSecurityException {
        // Mandatory algorithm
        KeyEncryptionAlgorithms keyEncryptionAlgorithm =
                KeyEncryptionAlgorithms.getAlgorithmFromId(
                        innerObject.getObject(ALGORITHM_LABEL).getInt());
 
        // Fetch public key if there is one
        PublicKey optionalPublicKey = null;
        if (innerObject.hasKey(PUBLIC_KEY_LABEL)) {
            optionalPublicKey = CBORPublicKey.decode(innerObject.getObject(PUBLIC_KEY_LABEL));
            // Please select ONE method for identifying the decryption key.
            CBORSigner.checkKeyId(optionalKeyId);
        }

        // Now we have what it takes for finding the proper private key
        PrivateKey privateKey = keyLocator.locate(optionalPublicKey,
                                                  optionalKeyId,
                                                  contentEncryptionAlgorithm,
                                                  keyEncryptionAlgorithm);

        // Fetch ephemeral key if applicable
        PublicKey ephemeralKey = null;
        if (!keyEncryptionAlgorithm.isRsa()) {
            ephemeralKey = CBORPublicKey.decode(innerObject.getObject(EPHEMERAL_KEY_LABEL));
        }
        
        // Fetch encrypted key if applicable
        byte[] encryptedKey = null;
        if (keyEncryptionAlgorithm.isKeyWrap()) {
            encryptedKey = innerObject.getObject(CIPHER_TEXT_LABEL).getByteString();
        }
        return keyEncryptionAlgorithm.isRsa() ?
            EncryptionCore.rsaDecryptKey(keyEncryptionAlgorithm, 
                                         encryptedKey,
                                         privateKey)
                                              :
            EncryptionCore.receiverKeyAgreement(true,
                                                keyEncryptionAlgorithm,
                                                contentEncryptionAlgorithm,
                                                ephemeralKey,
                                                privateKey,
                                                encryptedKey);
    }
}
