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

import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.KeyEncryptionAlgorithms;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Class for asymmetric key encryption.
 */
public class CBORAsymKeyEncrypter extends CBOREncrypter {

    KeyEncryptionAlgorithms keyEncryptionAlgorithm;

    boolean wantPublicKey;
    PublicKey publicKey;
    
    /**
     * Initializes an encrypter object.
     * 
     * @param publicKey Encryption key
     * @param keyEncryptionAlgorithm Key encryption algorithm
     * @param contentEncryptionAlgorithm Content encryption algorithm
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public CBORAsymKeyEncrypter(PublicKey publicKey,
                                KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                ContentEncryptionAlgorithms contentEncryptionAlgorithm) 
            throws IOException, GeneralSecurityException {
        super(contentEncryptionAlgorithm);
        this.publicKey = publicKey;
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
    }

    /**
     * Defines if public key should be included.
     * 
     * @param wantPublicKey Flag.  Default: false.
     * @return <code>this</code>
     */
    public CBORAsymKeyEncrypter setPublicKeyOption(boolean wantPublicKey) {
        this.wantPublicKey = wantPublicKey;
        return this;
    }
 
    @Override
    byte[] getContentEncryptionKey(CBORMap keyEncryption)
            throws IOException, GeneralSecurityException {
        
        // We may want to include the public key as well
        if (wantPublicKey) {
            keyEncryption.setObject(PUBLIC_KEY_LABEL, CBORPublicKey.encode(publicKey));
            // Which does not go together with a keyId
            CBORCryptoUtils.rejectPossibleKeyId(optionalKeyId);
        }
        
        // Create common key encryption data and return content encryption key. 
        return CBORCryptoUtils.setupBasicKeyEncryption(publicKey,
                                                       keyEncryption,
                                                       keyEncryptionAlgorithm,
                                                       contentEncryptionAlgorithm);
    }
}
