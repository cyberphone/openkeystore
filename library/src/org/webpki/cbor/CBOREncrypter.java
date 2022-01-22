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

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Base class for creating CBOR encryption objects.
 * 
 * It uses COSE algorithms but relies on CEF for the packaging.
 */
public abstract class CBOREncrypter {

    // The algorithm to use with the contentEncryptionKey
    ContentEncryptionAlgorithms contentEncryptionAlgorithm;
    
    // Optional key ID
    CBORObject optionalKeyId;

    CBOREncrypter(ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
        this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
    }
    
    abstract byte[] getContentEncryptionKey(CBORMap encryptionObject)
            throws IOException, GeneralSecurityException;
    
    // Overridden by key encryption encrypters
    CBORMap getEncryptionObject(CBORMap original) throws IOException {
        return original;
    }
    
    /**
     * Sets optional key Id.
     * 
     * In the case the public key is not provided in the 
     * object, the encryption key may be tied to an identifier
     * known by the recipient.  How such an identifier
     * is used to retrieve the proper private key is up to a
     * convention between the parties using
     * a specific message scheme.  A keyId may be a database
     * index, a hash of the public key, or a text string.
     * <p>
     * For symmetric key-algorithms, a keyId or implicit key are
     * the only ways to retrieve the proper secret key.
     * </p>
     * <p>
     * Note that a <code>keyId</code> argument of <code>null</code> 
     * is equivalent to the default (= no <code>keyId</code>).
     * </p>
     * 
     * @param keyId A CBOR key Id or <code>null</code>
     * @return this
     */
    public CBOREncrypter setKeyId(CBORObject keyId) {
        this.optionalKeyId = keyId;
        return this;
    }

    /**
     * Sets optional key Id.
     * 
     * @param keyId A CBOR key Id
     * @return this
     */
    public CBOREncrypter setKeyId(int keyId) {
        return setKeyId(new CBORInteger(keyId));
    }

    /**
     * Sets optional key Id.
     * 
     * @param keyId A CBOR key Id
     * @return this
     */
    public CBOREncrypter setKeyId(String keyId) {
        return setKeyId(new CBORTextString(keyId));
    }

    /**
     * Encrypts data.
     * 
     * @param dataToEncrypt The data to encrypt
     * @return CBORMap CBOR encryption object
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public CBORMap encrypt(byte[] dataToEncrypt) throws IOException, GeneralSecurityException {

        // Create an empty encryption object.
        CBORMap encryptionObject = new CBORMap();
        
        // Add the mandatory content encryption algorithm.
        encryptionObject.setObject(ALGORITHM_LABEL,
                                   new CBORInteger(
                                           contentEncryptionAlgorithm.getCoseAlgorithmId()));

        // Possible key encryption kicks in here.
        CBORMap innerObject = getEncryptionObject(encryptionObject);
        byte[] contentEncryptionKey = getContentEncryptionKey(innerObject);

        // Add a key Id if there is one.
        if (optionalKeyId != null) {
            innerObject.setObject(KEY_ID_LABEL, optionalKeyId);
        }
        
        // Now we should have everything for encrypting the actual data.
        // Use current CBOR data as "AAD".
        
        // Note that the following operation depends on that the actual
        // CBOR implementation supports fully canonical (deterministic)
        // parsing and code generation! This implementation shows that
        // this is quite simple.
        byte[] authData = encryptionObject.internalEncode();
        
        // Create an initialization vector.
        byte[] iv = EncryptionCore.createIv(contentEncryptionAlgorithm);
        
        // Perform the actual encryption.
        EncryptionCore.SymmetricEncryptionResult result =
                EncryptionCore.contentEncryption(contentEncryptionAlgorithm,
                                                 contentEncryptionKey,
                                                 iv, 
                                                 dataToEncrypt, 
                                                 authData);

        // Complement the encryption object with the result of the content encryption.
        
        // Authentication Data (tag).
        encryptionObject.setObject(TAG_LABEL, new CBORByteString(result.getTag()));

        // Initialization Vector.
        encryptionObject.setObject(IV_LABEL, new CBORByteString(iv));

        // The encrypted data.
        encryptionObject.setObject(CIPHER_TEXT_LABEL, new CBORByteString(result.getCipherText()));

        // Finally, the thing we all longed(?) for!
        return encryptionObject;
    }
}
