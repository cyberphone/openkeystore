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
import java.security.PublicKey;

import org.webpki.crypto.encryption.ContentEncryptionAlgorithms;
import org.webpki.crypto.encryption.EncryptionCore;
import org.webpki.crypto.encryption.KeyEncryptionAlgorithms;

/**
 * Base class for creating CBOR decryption objects.
 * 
 * It uses COSE algorithms but not the packaging.
 */
public abstract class CBORDecrypter {

    // Actual deryption key
    byte[] contentDecryptionKey;
    
    // The algorithm to use with the contentEncryptionKey
    ContentEncryptionAlgorithms contentEncryptionAlgorithm;
    
    // For key encryption schemes
    KeyEncryptionAlgorithms keyEncryptionAlgorithm;
    
    // Optional key ID
    String optionalKeyId;
    
    // Optional public key
    PublicKey optionalPublicKey;

    // Ephemeral key
    PublicKey ephemeralKey;

    // Optional encrypted key
    byte[] encryptedKey;

    CBORDecrypter() {}
    
    void keyEncryption(CBORIntegerMap encryptionObject) 
            throws IOException, GeneralSecurityException {
    }
    
    byte[] readAndRemove(CBORIntegerMap encryptionObject, CBORInteger key) throws IOException {
        byte[] data = encryptionObject.getObject(key).getByteString();
        encryptionObject.removeObject(key);
        return data;
    }
    
    /**
     * Encrypt data.
     * 
     * @param encodedEncryptionObject CBOR encryption object
     * @return Decrypted data
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public byte[] decrypt(byte[] encodedEncryptionObject)
            throws IOException, GeneralSecurityException {

        // Decode encryption object.
        CBORIntegerMap encryptionObject = 
                CBORObject.decode(encodedEncryptionObject).getIntegerMap();
        
        // Get the mandatory content encryption algorithm.
        contentEncryptionAlgorithm =
                ContentEncryptionAlgorithms.getAlgorithmFromId(
                        encryptionObject.getObject(CBOREncrypter.ALGORITHM_LABEL).getInt());

        // Possible key encryption begins to kick in here.
        CBORIntegerMap innerObject;
        boolean keyEncryptionScheme = encryptionObject.hasKey(CBOREncrypter.KEY_ENCRYPTION_LABEL);
        if (keyEncryptionScheme) {
            innerObject = encryptionObject.getObject(
                    CBOREncrypter.KEY_ENCRYPTION_LABEL).getIntegerMap(); 
 
            // Mandatory algorithm
            keyEncryptionAlgorithm = KeyEncryptionAlgorithms.getAlgorithmFromId(
                    innerObject.getObject(CBOREncrypter.ALGORITHM_LABEL).getInt());
 
            // Fetch public key if there is one
            if (innerObject.hasKey(CBOREncrypter.PUBLIC_KEY_LABEL)) {
                optionalPublicKey = CBORPublicKey.decode(
                        innerObject.getObject(CBOREncrypter.PUBLIC_KEY_LABEL));
            }
            
            // Fetch ephemeral key if applicable
            if (!keyEncryptionAlgorithm.isRsa()) {
                ephemeralKey = CBORPublicKey.decode(
                        innerObject.getObject(CBOREncrypter.EPHEMERAL_KEY_LABEL));
            }
            
            // Fetch encrypted key if applicable
            if (keyEncryptionAlgorithm.isKeyWrap()) {
                encryptedKey =
                        innerObject.getObject(CBOREncrypter.CIPHER_TEXT_LABEL).getByteString();
            }
            
        } else {
            innerObject = encryptionObject;
        }
             
        // Get the key Id if there is one.
        if (innerObject.hasKey(CBOREncrypter.KEY_ID_LABEL)) {
            optionalKeyId = innerObject.getObject(CBOREncrypter.KEY_ID_LABEL).getTextString();
        }
        
        // If the decrypter is into key encryption it will act.
        keyEncryption(innerObject);
        
        // Read and remove the content encryption parameters.
        byte[] iv = readAndRemove(encryptionObject, CBOREncrypter.IV_LABEL);
        byte[] tag = readAndRemove(encryptionObject, CBOREncrypter.TAG_LABEL);
        byte[] cipherText = readAndRemove(encryptionObject, CBOREncrypter.CIPHER_TEXT_LABEL);
        
        // Check that there is no unread (illegal) data.
        encryptionObject.checkObjectForUnread();
        
        // Now we should have everything for decrypting the actual data.
        // Use all current CBOR data as "authData".
        byte[] authData = encryptionObject.encode();
         
        // Perform the actual decryption.
        return EncryptionCore.contentDecryption(contentEncryptionAlgorithm,
                                                contentDecryptionKey,
                                                cipherText, 
                                                iv, 
                                                authData,
                                                tag);
    }
}
