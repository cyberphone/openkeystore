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

import org.webpki.cbor.CBORCryptoUtils.POLICY;
import org.webpki.cbor.CBORCryptoUtils.Collector;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Base class for decrypting data.
 * <p>
 * See also {@link CBOREncrypter}.
 * </p>
  * <p>
 * Note that decrypter objects may be used any number of times
 * (assuming that the same parameters are valid).  They are also
 * thread-safe.
 * </p>
 */
public abstract class CBORDecrypter <T extends CBORDecrypter<?>> {

    CBORDecrypter() {}
    
    abstract byte[] getContentEncryptionKey(CBORMap innerObject,
                                            ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                                            CBORObject optionalKeyId);
 
    abstract T getThis();

    POLICY customDataPolicy = POLICY.FORBIDDEN;
    Collector customDataCallBack;
    
    /**
     * Set custom extension data policy.
     * <p>
     * By default custom data elements ({@link CBORCryptoConstants#CXF_CUSTOM_DATA_LBL}) 
     * are rejected ({@link CBORCryptoUtils.POLICY#FORBIDDEN}).
     * </p>
     * <p>
     * See also <a href='doc-files/crypto-options.html' class='webpkilink'>crypto options</a>.
     * </p>
     * @param customDataPolicy Define level of support
     * @param customDataCallBack Interface for reading custom data
     * @return <code>this</code> of subclass
     */
    public T setCustomDataPolicy(POLICY customDataPolicy, Collector customDataCallBack) {
        this.customDataPolicy = customDataPolicy;
        this.customDataCallBack = customDataCallBack;
        return getThis();
    }

    POLICY tagPolicy = POLICY.FORBIDDEN;
    Collector tagCallBack;

    /**
     * Set tag wrapping policy.
     * <p>
     * By default wrapped containers are rejected ({@link CBORCryptoUtils.POLICY#FORBIDDEN}).
     * </p>
     * <p>
     * See also <a href='doc-files/crypto-options.html' class='webpkilink'>crypto options</a>.
     * </p>
     * @param tagPolicy Define level of support
     * @param tagCallBack Interface for reading tag
     * @return <code>this</code> of subclass
     */
    public T setTagPolicy(POLICY tagPolicy, Collector tagCallBack) {
        this.tagPolicy = tagPolicy;
        this.tagCallBack = tagCallBack;
        return getThis();
    }    
 
    /**
     * Decrypt data.
     * <p>
     * This method presumes that <code>encryptionObject</code> holds
     * an encryption object according to CEF.
     * </p>
     * 
     * @param encryptionObject CBOR encryption object
     * @return Decrypted data
     */
    public byte[] decrypt(CBORObject encryptionObject) {

        // There may be a tag holding the encryption container object (main map).
        CBORMap cefContainer = CBORCryptoUtils.unwrapContainerMap(encryptionObject,
                                                                  tagPolicy,
                                                                  tagCallBack);

        // Get the mandatory content encryption algorithm.
        ContentEncryptionAlgorithms contentEncryptionAlgorithm =
                ContentEncryptionAlgorithms.getAlgorithmFromId(
                        cefContainer.get(CXF_ALGORITHM_LBL).getInt32());

        // Possible key encryption kicks in here.  That is, there is a sub map.
        CBORMap innerObject = this instanceof CBORSymKeyDecrypter ? 
                cefContainer : cefContainer.get(CEF_KEY_ENCRYPTION_LBL).getMap();
              
        // Fetch optional keyId.
        CBORObject optionalKeyId = CBORCryptoUtils.getKeyId(innerObject);

        // Special handling of custom data.
        CBORCryptoUtils.getCustomData(cefContainer, customDataPolicy, customDataCallBack);

        // Get the content encryption key which also may be encrypted.
        byte[] contentDecryptionKey = getContentEncryptionKey(innerObject,
                                                              contentEncryptionAlgorithm,
                                                              optionalKeyId);
        
        // Read and remove the encryption object (map) parameters that
        // do not participate (because they cannot) in "authData".
        byte[] iv = cefContainer.remove(CEF_IV_LBL).getBytes();
        byte[] tag = cefContainer.remove(CEF_TAG_LBL).getBytes();
        byte[] cipherText = cefContainer.remove(CEF_CIPHER_TEXT_LBL).getBytes();
        
        // Check that there is no unread (illegal) data like public 
        // keys in symmetric encryption or just plain unknown elements.
        cefContainer.checkForUnread();
        
        // Now we should have everything for decrypting the actual data.
        // Use the remaining CBOR data as "authData" (AAD).
        
        // Note that the following operation depends on that the CBOR
        // implementation supports deterministic encoding and decoding.
        byte[] authData = encryptionObject.encode();
        
        // Be nice and restore the object as well.
        cefContainer.set(CEF_IV_LBL, new CBORBytes(iv));
        cefContainer.set(CEF_TAG_LBL, new CBORBytes(tag));
        cefContainer.set(CEF_CIPHER_TEXT_LBL, new CBORBytes(cipherText));
         
        // Perform the actual decryption.
        return EncryptionCore.contentDecryption(contentEncryptionAlgorithm,
                                                contentDecryptionKey,
                                                cipherText, 
                                                iv, 
                                                authData,
                                                tag);
    }
}
