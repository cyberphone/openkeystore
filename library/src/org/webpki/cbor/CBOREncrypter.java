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

import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.EncryptionCore;

import static org.webpki.cbor.CBORCryptoConstants.*;

import org.webpki.cbor.CBORCryptoUtils.Intercepter;

/**
 * Base class for encrypting data.
 * <p>
 * This implementation supports encryptions using 
 * <a title='CEF' target='_blank'
 * href='doc-files/encryption.html'>CEF</a>
 * (CBOR Encryption Format) packaging, while algorithms are derived from COSE.
 * </p>
 * <p>
 * Note that encrypter objects may be used any number of times
 * (assuming that the same parameters are valid).  They are also
 * thread-safe.
 * </p>
 * @see CBORDecrypter
 */
public abstract class CBOREncrypter {

    // The default is to use a map without tagging and custom data.
    Intercepter intercepter = new Intercepter() { };
    
    // The algorithm to use with the contentEncryptionKey
    ContentEncryptionAlgorithms contentEncryptionAlgorithm;
    
    // Optional key ID
    CBORObject optionalKeyId;

    CBOREncrypter(ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
        this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
    }
    
    abstract byte[] getContentEncryptionKey(CBORMap encryptionObject);
    
    /**
     * Sets optional Intercepter.
     * 
     * @param intercepter An instance of Intercepter
     * @return <code>this</code>
     */
    public CBOREncrypter setIntercepter(Intercepter intercepter) {
        this.intercepter = intercepter;
        return this;
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
     * @param keyId Key Id or <code>null</code>
     * @return <code>this</code>
     */
    public CBOREncrypter setKeyId(CBORObject keyId) {
        this.optionalKeyId = keyId;
        return this;
    }

    /**
     * Sets optional key Id.
     * 
     * The <code>keyId</code> will be represented as a CBOR <code>integer</code>.
     * 
     * @param keyId Key Id
     * @return <code>this</code>
     */
    public CBOREncrypter setKeyId(int keyId) {
        return setKeyId(new CBORInteger(keyId));
    }

    /**
     * Sets optional key Id.
     * 
     * The <code>keyId</code> will be represented as a CBOR <code>text&nbsp;string</code>.
     * 
     * @param keyId Key Id
     * @return <code>this</code>
     */
    public CBOREncrypter setKeyId(String keyId) {
        return setKeyId(new CBORString(keyId));
    }

    /**
     * Encrypts data.
     * 
     * @param dataToEncrypt The data to encrypt
     * @return CBOR encryption object
     */
    public CBORObject encrypt(byte[] dataToEncrypt) {

        // Create an empty encryption container object.
        CBORMap cefContainer = new CBORMap();

        // The encryption object may optionally be wrapped in a tag.
        CBORObject outerObject = intercepter.wrap(cefContainer);

        // Get optional custom data.
        CBORObject customData = intercepter.getCustomData();
        if (customData != null) {
            cefContainer.setObject(CUSTOM_DATA_LABEL, customData);
        }

        // Add the mandatory content encryption algorithm.
        cefContainer.setObject(ALGORITHM_LABEL,
                               new CBORInteger(contentEncryptionAlgorithm.getCoseAlgorithmId()));

        // Possible key encryption kicks in here.
        CBORMap innerObject;
        if (this instanceof CBORSymKeyEncrypter) {
            innerObject = cefContainer;
        } else {
            innerObject = new CBORMap();
            cefContainer.setObject(KEY_ENCRYPTION_LABEL, innerObject);
        }

        // Get the content encryption key which also may be encrypted.
        byte[] contentEncryptionKey = getContentEncryptionKey(innerObject);

        // Add a key Id if there is one.
        if (optionalKeyId != null) {
            innerObject.setObject(KEY_ID_LABEL, optionalKeyId);
        }
        
        // Now we should have everything for encrypting the actual data.
        // Use current CBOR data as "AAD".
        byte[] authData = outerObject.encode();
        
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
        cefContainer.setObject(TAG_LABEL, new CBORBytes(result.getTag()));

        // Initialization Vector.
        cefContainer.setObject(IV_LABEL, new CBORBytes(iv));

        // The encrypted data.
        cefContainer.setObject(CIPHER_TEXT_LABEL, new CBORBytes(result.getCipherText()));

        // Finally, the thing we all longed(?) for!
        return outerObject;
    }
}
