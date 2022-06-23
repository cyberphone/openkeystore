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

import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.EncryptionCore;

import static org.webpki.cbor.CBORCryptoConstants.*;

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
    
    /**
     * Decrypts data.
     * <p>
     * This method presumes that <code>encryptionObject</code> holds
     * an encryption object according to CEF.
     * </p>
     * <p>
     * Note that if <code>encryptionObject</code> holds a CBOR
     * <code>tag</code> object the <code>tag</code> must in turn contain the actual
     * encryption object.
     * Such a <code>tag</code> is also included in the authenticated data.
     * See {@link CBORCryptoUtils#unwrapContainerMap(CBORObject)} for details.
     * </p>
     * @param encryptionObject CBOR encryption object
     * @return Decrypted data
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public byte[] decrypt(CBORObject encryptionObject) throws IOException, 
                                                              GeneralSecurityException {

        // There may be a tag holding the encryption map.
        CBORMap encryptionMap = CBORCryptoUtils.unwrapContainerMap(encryptionObject);

        // Get the mandatory content encryption algorithm.
        ContentEncryptionAlgorithms contentEncryptionAlgorithm =
                ContentEncryptionAlgorithms.getAlgorithmFromId(
                        encryptionMap.getObject(ALGORITHM_LABEL).getInt());

        // Possible key encryption begins to kick in here.
        CBORMap innerObject = this instanceof CBORSymKeyDecrypter ? 
                encryptionMap : encryptionMap.getObject(KEY_ENCRYPTION_LABEL).getMap();
              
        // Get the key Id if there is one.
        CBORObject optionalKeyId = innerObject.hasKey(KEY_ID_LABEL) ?
                         innerObject.getObject(KEY_ID_LABEL).scan() : null;

        // Access a possible customData element in order satisfy checkForUnread().
        if (encryptionMap.hasKey(CUSTOM_DATA_LABEL)) {
            encryptionMap.getObject(CUSTOM_DATA_LABEL).scan();
        }

        // Get the content encryption key which also may be encrypted.
        byte[] contentDecryptionKey = getContentEncryptionKey(innerObject,
                                                              contentEncryptionAlgorithm,
                                                              optionalKeyId);
        
        // Read and remove the encryption object (map) parameters that
        // do not participate (because they cannot) in "authData".
        byte[] iv = encryptionMap.readByteStringAndRemoveKey(IV_LABEL);
        byte[] tag = encryptionMap.readByteStringAndRemoveKey(TAG_LABEL);
        byte[] cipherText = encryptionMap.readByteStringAndRemoveKey(CIPHER_TEXT_LABEL);
        
        // Check that there is no unread (illegal) data like public 
        // keys in symmetric encryption or just plain unknown elements.
        encryptionMap.checkForUnread();
        
        // Now we should have everything for decrypting the actual data.
        // Use the remaining CBOR data as "authData".
        
        // Note that the following operation depends on that the actual
        // CBOR implementation supports fully canonical (deterministic)
        // parsing and code generation! This implementation shows that
        // this is quite simple.
        byte[] authData = encryptionObject.internalEncode();
        
        // Be nice and restore the object as well.
        encryptionMap.setByteString(IV_LABEL, iv);
        encryptionMap.setByteString(TAG_LABEL, tag);
        encryptionMap.setByteString(CIPHER_TEXT_LABEL, cipherText);
         
        // Perform the actual decryption.
        return EncryptionCore.contentDecryption(contentEncryptionAlgorithm,
                                                contentDecryptionKey,
                                                cipherText, 
                                                iv, 
                                                authData,
                                                tag);
    }
}
