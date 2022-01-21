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

import org.webpki.crypto.encryption.ContentEncryptionAlgorithms;
import org.webpki.crypto.encryption.EncryptionCore;

/**
 * Base class for creating CBOR decryption objects.
 * 
 * It uses COSE algorithms but relies on CEF for the packaging.
 */
public abstract class CBORDecrypter {

    CBORDecrypter() {}
    
    abstract byte[] getContentEncryptionKey(CBORMap innerObject,
                                            ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                                            CBORObject optionalKeyId) 
            throws IOException, GeneralSecurityException;
    
    CBORMap getOptionalKeyEncryptionObject(CBORMap encryptionObject) throws IOException {
        return encryptionObject;
    }
    
    /**
     * Decrypts data.
     * 
     * @param encodedEncryptionObject CBOR encryption object
     * @return Decrypted data
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public byte[] decrypt(byte[] encodedEncryptionObject)
            throws IOException, GeneralSecurityException {

        // Decode encryption object.
        CBORMap encryptionObject = 
                CBORObject.decode(encodedEncryptionObject).getMap();
        
        // Get the mandatory content encryption algorithm.
        ContentEncryptionAlgorithms contentEncryptionAlgorithm =
                ContentEncryptionAlgorithms.getAlgorithmFromId(
                        encryptionObject.getObject(CBOREncrypter.ALGORITHM_LABEL).getInt());

        // Possible key encryption begins to kick in here.
        CBORMap innerObject = getOptionalKeyEncryptionObject(encryptionObject);
             
        // Get the key Id if there is one.
        CBORObject optionalKeyId = innerObject.hasKey(CBOREncrypter.KEY_ID_LABEL) ?
            innerObject.getObject(CBOREncrypter.KEY_ID_LABEL).scan() : null;
        
        // Get the content encryption key which also may be encrypted 
        byte[] contentDecryptionKey = getContentEncryptionKey(innerObject,
                                                              contentEncryptionAlgorithm,
                                                              optionalKeyId);
        
        // Read and remove the encryption object (map) parameters that
        // do not participate (because they cannot) in "authData".
        byte[] iv = CBORValidator.readAndRemove(encryptionObject, CBOREncrypter.IV_LABEL);
        byte[] tag = CBORValidator.readAndRemove(encryptionObject, CBOREncrypter.TAG_LABEL);
        byte[] cipherText = CBORValidator.readAndRemove(encryptionObject, 
                                                        CBOREncrypter.CIPHER_TEXT_LABEL);
        
        // Check that there is no unread (illegal) data like public 
        // keys in symmetric encryption or just plain unknown elements.
        encryptionObject.checkForUnread();
        
        // Now we should have everything for decrypting the actual data.
        // Use the remaining CBOR data as "authData".
        
        // Note that the following operation depends on that the actual
        // CBOR implementation supports fully canonical (deterministic)
        // parsing and code generation! This implementation shows that
        // this is quite simple.
        byte[] authData = encryptionObject.internalEncode();
         
        // Perform the actual decryption.
        return EncryptionCore.contentDecryption(contentEncryptionAlgorithm,
                                                contentDecryptionKey,
                                                cipherText, 
                                                iv, 
                                                authData,
                                                tag);
    }
}
