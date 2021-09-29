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
 * Base class for creating CBOR encryption objects.
 * 
 * It uses COSE algorithms but not COSE packaging.
 */
public abstract class CBOREncrypter {

    /**
     * Integer value: 1.
     * Note: This label is also used in key encryption sub-maps.
     */
    public static final CBORInteger ALGORITHM_LABEL      = new CBORInteger(1);
    
    /**
     * Integer value: 2.
     * This label holds a key encryption sub-map.
     */
    public static final CBORInteger KEY_ENCRYPTION_LABEL = new CBORInteger(2);

    /**
     * Integer value: 3.
     * Note: This label is alternatively used in key encryption sub-maps.
     */
    public static final CBORInteger KEY_ID_LABEL         = new CBORInteger(3);
    
    /**
     * Integer value: 4.
     * Note: This label is only used in key encryption sub-maps.
     */
    public static final CBORInteger PUBLIC_KEY_LABEL     = new CBORInteger(4);

    /**
     * Integer value: 5.
     * Note: This label is only used in key encryption sub-maps.
     */
    public static final CBORInteger EPHEMERAL_KEY_LABEL  = new CBORInteger(5);

    /**
     * Integer value: 6.
     * Note: This label is only used in key encryption sub-maps.
     */
    public static final CBORInteger CERT_PATH_LABEL      = new CBORInteger(6);
 
    /**
     * Integer value: 7.
     */
    public static final CBORInteger TAG_LABEL            = new CBORInteger(7);
 
    /**
     * Integer value: 8.
     */
    public static final CBORInteger IV_LABEL             = new CBORInteger(8);

    /**
     * Integer value: 9.
     * Note: This label is also used in key encryption sub-maps using key-wrapping.
     */
    public static final CBORInteger CIPHER_TEXT_LABEL    = new CBORInteger(9);

    // The algorithm to use with the contentEncryptionKey
    ContentEncryptionAlgorithms contentEncryptionAlgorithm;
    
    // Optional key ID
    byte[] keyId;

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
     * Set encryption key Id.
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
     * 
     * @param keyId A key Id byte array
     * @return this
     */
    public CBOREncrypter setKeyId(byte[] keyId) {
        this.keyId = keyId;
        return this;
    }

    /**
     * Encrypt data.
     * 
     * @param dataToEncrypt The data to encrypt
     * @return CBORMap CBOR encryption object
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public CBORMap encrypt(byte[] dataToEncrypt) throws IOException,
                                                        GeneralSecurityException {
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
        if (keyId != null) {
            innerObject.setObject(KEY_ID_LABEL, new CBORByteString(keyId));
        }
        
        // Now we should have everything for encrypting the actual data.
        // Use current CBOR data as "authData".
        
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
