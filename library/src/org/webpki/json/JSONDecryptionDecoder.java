/*
 *  Copyright 2006-2018 WebPKI.org (http://webpki.org).
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
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;

import java.util.LinkedHashMap;
import java.util.Vector;

////////////////////////////////////////////////////////////////////////////////////
// JEF is effectively a "remake" of of JWE.  Why a remake?  Because the           //
// encryption system (naturally) borrows heavily from JSF including clear text    //
// header information and using the JCS based normalization scheme for creating   //
// authenticated data.                                                            //
//                                                                                //
// The supported algorithms and JWK attributes are though fully JOSE compatible.  //
////////////////////////////////////////////////////////////////////////////////////

/**
 * Holds parsed JEF (JSON Encryption Format) data.
 */
public class JSONDecryptionDecoder {

    /**
     * Decodes and hold all global data and options.
     */
    static class Holder {

        JSONCryptoHelper.Options options;
        
        boolean keyEncryption;

        byte[] authenticatedData;
        byte[] iv;
        byte[] tag;
        byte[] encryptedData;
        
        DataEncryptionAlgorithms dataEncryptionAlgorithm;
        JSONObjectReader globalEncryptionObject;

        Holder (JSONCryptoHelper.Options options, 
                JSONObjectReader encryptionObject,
                boolean keyEncryption) throws IOException {
            encryptionObject.clearReadFlags();
            this.options = options;
            this.globalEncryptionObject = encryptionObject;
            this.keyEncryption = keyEncryption;

            ///////////////////////////////////////////////////////////////////////////////////////////////
            // Begin JEF normalization                                                                   //
            //                                                                                           //
            // 1. Make a shallow copy of the encryption object property list                             //
            LinkedHashMap<String, JSONValue> savedProperties =                                           //
                    new LinkedHashMap<String, JSONValue>(encryptionObject.root.properties);              //
            //                                                                                           //
            // 2. Hide these properties from the serializer..                                            //
            encryptionObject.root.properties.remove(JSONCryptoHelper.IV_JSON);                           //
            encryptionObject.root.properties.remove(JSONCryptoHelper.TAG_JSON);                          //
            encryptionObject.root.properties.remove(JSONCryptoHelper.CIPHER_TEXT_JSON);                  //
            //                                                                                           //
            // 3. Canonicalize                                                                           //
            authenticatedData = encryptionObject.serializeToBytes(JSONOutputFormats.CANONICALIZED);      //
            //                                                                                           //
            // 4. Restore encryption object property list                                                //
            encryptionObject.root.properties = savedProperties;                                          //
            //                                                                                           //
            // End JEF normalization                                                                     //
            ///////////////////////////////////////////////////////////////////////////////////////////////

            // Collect mandatory elements
            dataEncryptionAlgorithm = DataEncryptionAlgorithms
                    .getAlgorithmFromId(encryptionObject.getString(JSONCryptoHelper.ALGORITHM_JSON));
            iv = encryptionObject.getBinary(JSONCryptoHelper.IV_JSON);
            tag = encryptionObject.getBinary(JSONCryptoHelper.TAG_JSON);
            encryptedData = encryptionObject.getBinary(JSONCryptoHelper.CIPHER_TEXT_JSON);
        }
    }

    LinkedHashMap<String,JSONCryptoHelper.Extension> extensions = new LinkedHashMap<String,JSONCryptoHelper.Extension>();

    private PublicKey publicKey;
    
    private X509Certificate[] certificatePath;

    private ECPublicKey ephemeralPublicKey;  // For ECHD only

    private String keyId;

    private KeyEncryptionAlgorithms keyEncryptionAlgorithm;

    private byte[] encryptedKeyData;  // For RSA and ECDH+ only

    private boolean sharedSecretMode;

    private Holder holder;

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public X509Certificate[] getCertificatePath() {
        return certificatePath;
    }

    public boolean isSharedSecret() {
        return sharedSecretMode;
    }

    public JSONDecryptionDecoder require(boolean publicKeyEncryption) throws IOException {
        if (publicKeyEncryption == sharedSecretMode) {
            throw new IOException((publicKeyEncryption ? "Missing" : "Unexpected") + " public key");
        }
        return this;
    }

    public String getKeyId() {
        return keyId;
    }

    public DataEncryptionAlgorithms getDataEncryptionAlgorithm() {
        return holder.dataEncryptionAlgorithm;
    }

    public KeyEncryptionAlgorithms getKeyEncryptionAlgorithm() {
        return keyEncryptionAlgorithm;
    }

    /**
     * Decodes a single encryption element.
     * @param holder Global data
     * @param encryptionObject JSON input data
     * @param last <code>true</code> if this is the final encryption object
     * @throws IOException
     */
    JSONDecryptionDecoder(Holder holder, 
                          JSONObjectReader encryptionObject,
                          boolean last) throws IOException {
        this.holder = holder;

        // Collect keyId if such are permitted
        keyId = holder.options.getKeyId(encryptionObject);

        // Are we using a key encryption scheme?
        if (holder.keyEncryption)  {
            keyEncryptionAlgorithm = KeyEncryptionAlgorithms
                        .getAlgorithmFromId(encryptionObject.getString(JSONCryptoHelper.ALGORITHM_JSON));
            if (keyEncryptionAlgorithm == null) {
                throw new IOException("Missing \"" + JSONCryptoHelper.ALGORITHM_JSON  + "\"");
            }
            if (holder.options.requirePublicKeyInfo) {
                if (encryptionObject.hasProperty(JSONCryptoHelper.CERTIFICATE_PATH_JSON)) {
                    certificatePath = encryptionObject.getCertificatePath();
                } else if (encryptionObject.hasProperty(JSONCryptoHelper.PUBLIC_KEY_JSON)) {
                    publicKey = encryptionObject.getPublicKey(holder.options.algorithmPreferences);
                } else {
                    throw new IOException("Missing key information");
                }
            }

            if (keyEncryptionAlgorithm.isKeyWrap()) {
                encryptedKeyData = encryptionObject.getBinary(JSONCryptoHelper.CIPHER_TEXT_JSON);
            }
            if (!keyEncryptionAlgorithm.isRsa()) {
                ephemeralPublicKey =
                        (ECPublicKey) encryptionObject
                            .getObject(JSONCryptoHelper.EPHEMERAL_KEY_JSON)
                                .getCorePublicKey(holder.options.algorithmPreferences);
            }
        } else {
            sharedSecretMode = true;
        }

        // An encryption object may also hold "extension" data
        holder.options.getExtensions(encryptionObject, holder.globalEncryptionObject, extensions);

        if (last) {
            // The MUST NOT be any unknown elements inside of a JEF object
            holder.globalEncryptionObject.checkForUnread();
        }
    }

    private byte[] localDecrypt(byte[] dataDecryptionKey) throws IOException, GeneralSecurityException {
        return EncryptionCore.contentDecryption(holder.dataEncryptionAlgorithm,
                                                dataDecryptionKey,
                                                holder.encryptedData,
                                                holder.iv,
                                                holder.authenticatedData,
                                                holder.tag);
    }

    /**
     * Decrypt data based on a specific symmetric key.
     * @param dataDecryptionKey Symmetric key
     * @return Decrypted data
     * @throws IOException &nbsp;
     * @throws GeneralSecurityException &nbsp;
     */
    public byte[] getDecryptedData(byte[] dataDecryptionKey) throws IOException, GeneralSecurityException {
        require(false);
        return localDecrypt(dataDecryptionKey);
    }

    /**
     * Decrypt data based on a specific private key.
     * @param privateKey The private key
     * @return Decrypted data
     * @throws IOException &nbsp;
     * @throws GeneralSecurityException &nbsp;
     */
    public byte[] getDecryptedData(PrivateKey privateKey) throws IOException, GeneralSecurityException {
        require(true);
        return localDecrypt(keyEncryptionAlgorithm.isRsa() ?
                EncryptionCore.rsaDecryptKey(keyEncryptionAlgorithm,
                                             encryptedKeyData,
                                             privateKey)
                                                           :
                EncryptionCore.receiverKeyAgreement(keyEncryptionAlgorithm,
                                                    holder.dataEncryptionAlgorithm,
                                                    ephemeralPublicKey,
                                                    privateKey,
                                                    encryptedKeyData));
    }

    /**
     * Decrypt data based on a collection of possible [private] keys.
     * @param decryptionKeys Collection
     * @return Decrypted data
     * @throws IOException &nbsp;
     * @throws GeneralSecurityException &nbsp;
     */
    public byte[] getDecryptedData(Vector<DecryptionKeyHolder> decryptionKeys)
    throws IOException, GeneralSecurityException {
        boolean notFound = true;
        for (DecryptionKeyHolder decryptionKey : decryptionKeys) {
            if ((decryptionKey.getKeyId() != null && decryptionKey.getKeyId().equals(keyId)) || 
                decryptionKey.getPublicKey().equals(publicKey)) {
                notFound = false;
                if (decryptionKey.getKeyEncryptionAlgorithm().equals(keyEncryptionAlgorithm)) {
                    return getDecryptedData(decryptionKey.getPrivateKey());
                }
            }
        }
        throw new IOException(notFound ? "No matching key found" : "No matching key+algorithm found");
    }

    /**
     *  JEF (JSON Encryption Format) support.
     *  This class can be used for automatically selecting the proper asymmetric private key
     *  to use for decryption among a set of possible keys.
     */
    public static class DecryptionKeyHolder {

        PublicKey publicKey;

        PrivateKey privateKey;
        
        String optionalKeyId;

        KeyEncryptionAlgorithms keyEncryptionAlgorithm;

        public PublicKey getPublicKey() {
            return publicKey;
        }

        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        public String getKeyId() {
            return optionalKeyId;
        }

        public KeyEncryptionAlgorithms getKeyEncryptionAlgorithm() {
            return keyEncryptionAlgorithm;
        }

        public DecryptionKeyHolder(PublicKey publicKey, 
                                   PrivateKey privateKey,
                                   KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                   String optionalKeyId) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
            this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
            this.optionalKeyId = optionalKeyId;
        }
    }

    static void keyWrapCheck(KeyEncryptionAlgorithms keyEncryptionAlgorithm) throws IOException {
        if (!keyEncryptionAlgorithm.keyWrap) {
            throw new IOException("Multiple encryptions only permitted for key wrapping schemes");
        }
    }
}
