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
package org.webpki.json;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import java.util.LinkedHashSet;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.CryptoRandom;

import org.webpki.crypto.encryption.EncryptionCore;
import org.webpki.crypto.encryption.KeyEncryptionAlgorithms;
import org.webpki.crypto.encryption.ContentEncryptionAlgorithms;

/**
 * Support class for encryption generators.
 */
public abstract class JSONEncrypter {

    JSONObjectReader extensions;
    
    String keyId;

    boolean outputPublicKeyInfo = true;
    
    KeyEncryptionAlgorithms keyEncryptionAlgorithm;

    byte[] contentEncryptionKey;

    PublicKey publicKey;
    
    AlgorithmPreferences algorithmPreferences = AlgorithmPreferences.JOSE_ACCEPT_PREFER;

    JSONEncrypter() {
    }

    static class Header {

        ContentEncryptionAlgorithms contentEncryptionAlgorithm;

        JSONObjectWriter encryptionWriter;

        byte[] contentEncryptionKey;
        
        LinkedHashSet<String> foundExtensions = new LinkedHashSet<>();
        
        Header(ContentEncryptionAlgorithms contentEncryptionAlgorithm, JSONEncrypter encrypter) 
                throws IOException {
            this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
            contentEncryptionKey = encrypter.contentEncryptionKey;
            encryptionWriter = new JSONObjectWriter();
            encryptionWriter.setString(JSONCryptoHelper.ALGORITHM_JSON, 
                                       contentEncryptionAlgorithm.getJoseAlgorithmId());
            if (encrypter.keyEncryptionAlgorithm != null && 
                    encrypter.keyEncryptionAlgorithm.isKeyWrap()) {
                contentEncryptionKey = 
                        CryptoRandom.generateRandom(contentEncryptionAlgorithm.getKeyLength());
            }
        }

        void createRecipient(JSONEncrypter encrypter, JSONObjectWriter currentRecipient)
        throws IOException, GeneralSecurityException {
            if (encrypter.keyEncryptionAlgorithm != null) {
                currentRecipient.setString(JSONCryptoHelper.ALGORITHM_JSON, 
                                           encrypter.keyEncryptionAlgorithm.getJoseAlgorithmId());
            }

            if (encrypter.keyId != null) {
                currentRecipient.setString(JSONCryptoHelper.KEY_ID_JSON, encrypter.keyId);
            }

            if (encrypter.outputPublicKeyInfo) {
                encrypter.writeKeyData(currentRecipient);
            }
 
            // The encrypted key part (if any)
            if (encrypter.keyEncryptionAlgorithm != null) {
                EncryptionCore.AsymmetricEncryptionResult asymmetricEncryptionResult =
                        encrypter.keyEncryptionAlgorithm.isRsa() ?
                            EncryptionCore.rsaEncryptKey(contentEncryptionKey,
                                                         encrypter.keyEncryptionAlgorithm,
                                                         encrypter.publicKey)
                                                       :
                            EncryptionCore.senderKeyAgreement(false,
                                                              contentEncryptionKey,
                                                              encrypter.keyEncryptionAlgorithm,
                                                              contentEncryptionAlgorithm,
                                                              encrypter.publicKey);
                contentEncryptionKey = asymmetricEncryptionResult.getContentEncryptionKey();
                if (!encrypter.keyEncryptionAlgorithm.isRsa()) {
                    currentRecipient
                        .setObject(JSONCryptoHelper.EPHEMERAL_KEY_JSON,
                                   JSONObjectWriter
                                       .createCorePublicKey(
                                               asymmetricEncryptionResult.getEphemeralKey(),
                                               AlgorithmPreferences.JOSE));
                }
                if (encrypter.keyEncryptionAlgorithm.isKeyWrap()) {
                    currentRecipient.setBinary(JSONCryptoHelper.ENCRYPTED_KEY_JSON,
                                               asymmetricEncryptionResult.getEncryptedKeyData());
                }
            }

            if (encrypter.extensions != null) {
                for (String property : encrypter.extensions.getProperties()) {
                    foundExtensions.add(property);
                    currentRecipient.setProperty(property, 
                                                 encrypter.extensions.getProperty(property));
                }
            }
        }

        JSONObjectWriter finalizeEncryption(byte[] unencryptedData) 
        throws IOException, GeneralSecurityException {
            if (!foundExtensions.isEmpty()) {
                encryptionWriter.setStringArray(JSONCryptoHelper.EXTENSIONS_JSON,
                                                foundExtensions.toArray(new String[0]));
            }
            byte[] iv = EncryptionCore.createIv(contentEncryptionAlgorithm);
            EncryptionCore.SymmetricEncryptionResult symmetricEncryptionResult =
                EncryptionCore.contentEncryption(contentEncryptionAlgorithm,
                                                 contentEncryptionKey,
                                                 iv,
                                                 unencryptedData,
                                                 encryptionWriter.serializeToBytes(
                                                      JSONOutputFormats.CANONICALIZED));
            encryptionWriter.setBinary(JSONCryptoHelper.IV_JSON, iv);
            encryptionWriter.setBinary(JSONCryptoHelper.TAG_JSON,
                                       symmetricEncryptionResult.getTag());
            encryptionWriter.setBinary(JSONCryptoHelper.CIPHER_TEXT_JSON,
                                       symmetricEncryptionResult.getCipherText());
            return encryptionWriter;
        }
    }

    abstract void writeKeyData(JSONObjectWriter wr) throws IOException, GeneralSecurityException;

    /**
     * Set &quot;crit&quot; for this encryption object.
     * @param extensions JSON object holding the extension properties and associated values
     * @return this
     * @throws IOException
     */
    public JSONEncrypter setExtensions(JSONObjectWriter extensions) throws IOException {
        this.extensions = new JSONObjectReader(extensions);
        JSONCryptoHelper.checkExtensions(this.extensions.getProperties(), true);
        return this;
    }

    /**
     * Set optional &quot;kid&quot; for this encryption object.
     * @param keyId The identifier
     * @return this
     */
    public JSONEncrypter setKeyId(String keyId) {
        this.keyId = keyId;
        return this;
    }

    /**
     * Set if public key information should be provided in the encryption object.
     * Note: default <code>true</code>.
     * @param flag <code>true</code> if such information is to be provided
     * @return this
     */
    public JSONEncrypter setOutputPublicKeyInfo(boolean flag) {
        this.outputPublicKeyInfo = flag;
        return this;
    }
}
