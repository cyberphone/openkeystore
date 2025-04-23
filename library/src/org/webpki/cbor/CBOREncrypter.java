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

import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.EncryptionCore;

import static org.webpki.cbor.CBORCryptoConstants.*;

import org.webpki.cbor.CBORCryptoUtils.Intercepter;
import org.webpki.cbor.CBORCryptoUtils.POLICY;

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
public abstract class CBOREncrypter <T extends CBOREncrypter<T>>  {

    // The default is to use a map without custom data.
    Intercepter intercepter = new Intercepter() { };
    
    // The algorithm to use with the contentEncryptionKey
    ContentEncryptionAlgorithms contentEncryptionAlgorithm;
    
    // Optional key ID
    CBORObject optionalKeyId;

    CBOREncrypter(ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
        this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
    }
    
    abstract byte[] getContentEncryptionKey(CBORMap encryptionObject);

    abstract T getThis();
    
    /**
     * Set optional Intercepter.
     * 
     * @param intercepter An instance of Intercepter
     * @return <code>this</code> of subclass
     */
    public T setIntercepter(Intercepter intercepter) {
        this.intercepter = intercepter;
        return getThis();
    }
    
    /**
     * Set optional key Id.
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
     * @return <code>this</code> of substack
     */
    public T setKeyId(CBORObject keyId) {
        this.optionalKeyId = keyId;
        return getThis();
    }

    /**
     * Encrypt data, return tagged CEF object.
     * 
     * @param dataToEncrypt The data to encrypt
     * @param wrappedMap Empty map wrapped in a tag or <code>null</code>
     * @return CBOR encryption object
     */
    public CBORObject encrypt(byte[] dataToEncrypt, CBORTag wrappedMap) {

        // Empty encryption container object.
        CBORMap cefContainer;

        // The encryption object may optionally be wrapped in a tag.
        CBORObject outerObject;

        // There may be a tag holding an empty CEF map.
        if (wrappedMap == null) {
            outerObject = cefContainer = new CBORMap();
        } else {
            cefContainer = CBORCryptoUtils.unwrapContainerMap(wrappedMap, 
                                                              POLICY.OPTIONAL, 
                                                              null);
            outerObject = wrappedMap;
        }

        // Get optional custom data.
        CBORObject customData = intercepter.getCustomData();
        if (customData != null) {
            cefContainer.set(CXF_CUSTOM_DATA_LBL, customData);
        }

        // Add the mandatory content encryption algorithm.
        cefContainer.set(CXF_ALGORITHM_LBL, 
                         new CBORInt(contentEncryptionAlgorithm.getCoseAlgorithmId()));

        // Possible key encryption kicks in here.
        CBORMap innerObject;
        if (this instanceof CBORSymKeyEncrypter) {
            innerObject = cefContainer;
        } else {
            innerObject = new CBORMap();
            cefContainer.set(CEF_KEY_ENCRYPTION_LBL, innerObject);
        }

        // Get the content encryption key which also may be encrypted.
        byte[] contentEncryptionKey = getContentEncryptionKey(innerObject);

        // Add a key Id if there is one.
        if (optionalKeyId != null) {
            innerObject.set(CXF_KEY_ID_LBL, optionalKeyId);
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
        cefContainer.set(CEF_TAG_LBL, new CBORBytes(result.getTag()));

        // Initialization Vector.
        cefContainer.set(CEF_IV_LBL, new CBORBytes(iv));

        // The encrypted data.
        cefContainer.set(CEF_CIPHER_TEXT_LBL, new CBORBytes(result.getCipherText()));

        // Finally, the thing we all longed(?) for!
        return outerObject;
    }

    /**
     * Encrypt data, return CEF object.
     * 
     * @param dataToEncrypt The data to encrypt
     * @return CBOR encryption object
     */
    public CBORObject encrypt(byte[] dataToEncrypt) {
        return encrypt(dataToEncrypt, null);
    }
}
