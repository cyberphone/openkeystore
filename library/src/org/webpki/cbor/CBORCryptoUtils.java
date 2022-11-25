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
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.util.ArrayList;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.CryptoRandom;
import org.webpki.crypto.EncryptionCore;
import org.webpki.crypto.KeyEncryptionAlgorithms;
import org.webpki.crypto.SignatureWrapper;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Class holding crypto support 
 */
public class CBORCryptoUtils {
    
    CBORCryptoUtils() {}
    
    /**
     * Decodes a certificate path from a CBOR array.
 
     * Note that the array must only contain a
     * list of X509 certificates in DER format,
     * each encoded as a CBOR <code>byte&nbsp;string</code>. 
     * The certificates must be in ascending
     * order with respect to parenthood.  That is,
     * the first certificate would typically be
     * an end-entity certificate.
     * 
     * See {@link #encodeCertificateArray(X509Certificate[])}.
     * 
     * @return Certificate path
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static X509Certificate[] decodeCertificateArray(CBORArray array) 
            throws IOException, GeneralSecurityException {
        ArrayList<byte[]> blobs = new ArrayList<>();
        int index = 0;
        do {
            blobs.add(array.objectList.get(index).getByteString());
        } while (++index < array.objectList.size());
        return CertificateUtil.makeCertificatePath(blobs);
    }

    /**
     * Encodes certificate path into a CBOR array.
 
     * Note that the certificates must be in ascending
     * order with respect to parenthood.  That is,
     * the first certificate would typically be
     * an end-entity certificate.  The CBOR array
     * will after the conversion hold a list of
     * DER-encoded certificates, each represented by a CBOR
     * <code>byte&nbsp;string</code>.
     * 
     * See  {@link #decodeCertificateArray(CBORArray)}.
     * 
     * @param certificatePath The certificate path to be converted to CBOR 
     * 
     * @return CBORArray
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static CBORArray encodeCertificateArray(X509Certificate[] certificatePath) 
            throws IOException, GeneralSecurityException {
        CBORArray array = new CBORArray();
        for (X509Certificate certificate : CertificateUtil.checkCertificatePath(certificatePath)) {
            array.addObject(new CBORByteString(certificate.getEncoded()));
        }
        return array;
    }

    /**
     * Interface for customizing map objects.
     * <p>
     * Implementations of this interface must be set by calling
     * {@link CBORSigner#setIntercepter(Intercepter)} and
     * {@link CBOREncrypter#setIntercepter(Intercepter)} for
     * signatures and encryption respectively.
     * </p>
     */
    public interface Intercepter {

        /**
         * Optionally wraps a map in a tag.
         * <p>
         * See {@link CBORTag} for details on the syntax for wrapped CBOR data.
         * </p>
         * 
         * @param map Unwrapped map
         * @return Original (default implementation) or wrapped map
         * @throws IOException
         * @throws GeneralSecurityException
         */
        default CBORObject wrap(CBORMap map) 
                throws IOException, GeneralSecurityException {
            return map;
        }

        /**
         * Optionally adds custom data to the map.
         * <p>
         * Custom data may be any valid CBOR object.  This data is assigned
         * to the CSF/CEF specific label {@link CBORCryptoConstants#CUSTOM_DATA_LABEL}.
         * </p>
         * <p>
         * If this method returns <code>null</code>, the assumption is that there is no
         * custom data.
         * </p>
         * 
         * @return <code>null</code> (default implementation) or custom data object.
         * @throws IOException
         * @throws GeneralSecurityException
         */
        default CBORObject getCustomData() throws IOException, GeneralSecurityException {
            return null;
        }
    }

    /**
     * Interface for collecting tagged or custom data.
     * <p>
     * Implementations of this interface must be set by calling the
     * {@link CBORValidator#setCustomDataPolicy(POLICY,Collector)} and
     * {@link CBORDecrypter#setCustomDataPolicy(POLICY,Collector)} for
     * signatures and encryption respectively.
     * </p>
     */
    public interface Collector {

        /**
         * Returns tag or custom data.
         * 
         * @param objectOrNull If there is no tag or custom data this element is <code>null</code>
         *
         * @throws IOException
         * @throws GeneralSecurityException
         */
        void foundData(CBORObject objectOrNull) throws IOException, GeneralSecurityException;
    }
    
    /**
     * Policy regarding additional CSF and CEF features.
     */
    public static enum POLICY {FORBIDDEN, OPTIONAL, MANDATORY}
    
    static void inputError(String text, POLICY policy) throws IOException {
        CBORObject.reportError(String.format("%s. Policy: %s", text, policy.toString()));
    }
 
    static CBORMap unwrapContainerMap(CBORObject container, 
                                      POLICY tagPolicy,
                                      Collector callBackOrNull)
            throws IOException, GeneralSecurityException {
        if (container.getType() == CBORTypes.TAG) {
            if (tagPolicy == POLICY.FORBIDDEN) {
                inputError("Tag encountered", tagPolicy);
            }
            CBORTag tag = container.getTag();
            container = tag.object;
            if (tag.tagNumber == CBORTag.RESERVED_TAG_COTE) {
                container = container.getArray().getObject(1);
            }
            if (callBackOrNull != null) {
                callBackOrNull.foundData(tag);
            }
        } else if (tagPolicy == POLICY.MANDATORY) {
            inputError("Missing tag", tagPolicy);
        }
        return container.getMap();
    }
    
    static CBORObject getKeyId(CBORMap holderMap) throws IOException {

        // Get the key Id if there is one and scan() to make sure checkForUnread() won't fail
        return holderMap.hasKey(KEY_ID_LABEL) ?
            holderMap.getObject(KEY_ID_LABEL).scan() : null;
    }
    
    static void getCustomData(CBORMap holderMap, 
                              POLICY customDataPolicy,
                              Collector callBackOrNull) throws IOException,
                                                               GeneralSecurityException {
        // Get optional customData element.
        if (holderMap.hasKey(CUSTOM_DATA_LABEL)) {
            if (customDataPolicy == POLICY.FORBIDDEN) {
                inputError("Custom data encountered", customDataPolicy);
            }
            // It is OK to not read customData during validation.
            CBORObject customData = holderMap.getObject(CUSTOM_DATA_LABEL).scan();
            if (callBackOrNull != null) {
                callBackOrNull.foundData(customData);
            }
        } else if (customDataPolicy == POLICY.MANDATORY) {
            inputError("Missing custom data", customDataPolicy);
        }
    }
    
    static byte[] setupBasicKeyEncryption(PublicKey publicKey,
                                          CBORMap keyEncryption,
                                          KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                          ContentEncryptionAlgorithms contentEncryptionAlgorithm) 
            throws GeneralSecurityException, IOException {

        // The mandatory key encryption algorithm
        keyEncryption.setObject(ALGORITHM_LABEL,
                                new CBORInteger(keyEncryptionAlgorithm.getCoseAlgorithmId()));
        
        // Key wrapping algorithms need a key to wrap
        byte[] contentEncryptionKey = keyEncryptionAlgorithm.isKeyWrap() ?
            CryptoRandom.generateRandom(contentEncryptionAlgorithm.getKeyLength()) : null;
                                                                         
        // The core
        EncryptionCore.AsymmetricEncryptionResult asymmetricEncryptionResult =
                keyEncryptionAlgorithm.isRsa() ?
                    EncryptionCore.rsaEncryptKey(contentEncryptionKey,
                                                 keyEncryptionAlgorithm,
                                                 publicKey)
                                               :
                    EncryptionCore.senderKeyAgreement(true,
                                                      contentEncryptionKey,
                                                      keyEncryptionAlgorithm,
                                                      contentEncryptionAlgorithm,
                                                      publicKey);
        if (!keyEncryptionAlgorithm.isRsa()) {
            // ECDH-ES requires the ephemeral public key
            keyEncryption.setObject(EPHEMERAL_KEY_LABEL,
                                    CBORPublicKey.encode(
                                        asymmetricEncryptionResult.getEphemeralKey()));
        }
        if (keyEncryptionAlgorithm.isKeyWrap()) {
            // Encrypted key
            keyEncryption.setObject(CIPHER_TEXT_LABEL,
                                    new CBORByteString(
                                        asymmetricEncryptionResult.getEncryptedKey()));
        }
        return asymmetricEncryptionResult.getContentEncryptionKey();
    }
    
    static byte[] asymKeyDecrypt(PrivateKey privateKey,
                                 CBORMap innerObject,
                                 KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                 ContentEncryptionAlgorithms contentEncryptionAlgorithm)
            throws GeneralSecurityException, IOException {

        // Fetch encrypted key if applicable
        byte[] encryptedKey = keyEncryptionAlgorithm.isKeyWrap() ?
            innerObject.getObject(CIPHER_TEXT_LABEL).getByteString() : null;

        // The core
        return keyEncryptionAlgorithm.isRsa() ?
            EncryptionCore.rsaDecryptKey(keyEncryptionAlgorithm, 
                                         encryptedKey,
                                         privateKey)
                                              :
            EncryptionCore.receiverKeyAgreement(true,
                                                keyEncryptionAlgorithm,
                                                contentEncryptionAlgorithm,
                                                CBORPublicKey.decode(
                                                    innerObject.getObject(EPHEMERAL_KEY_LABEL)),
                                                privateKey,
                                                encryptedKey);
    }

    static void asymKeySignatureValidation(PublicKey publicKey,
                                           AsymSignatureAlgorithms signatureAlgorithm,
                                           byte[] signedData,
                                           byte[] signatureValue) 
            throws GeneralSecurityException, IOException {

        // Verify signature using the default provider
        if (!new SignatureWrapper(signatureAlgorithm, publicKey)
                 .update(signedData)
                 .verify(signatureValue)) {
            throw new GeneralSecurityException("Bad signature for key: " + publicKey.toString());
        }
    }

    static byte[] asymKeySignatureGeneration(PrivateKey privateKey,
                                             AsymSignatureAlgorithms algorithm,
                                             byte[] dataToBeSigned,
                                             String provider) 
            throws GeneralSecurityException, IOException {

        // Sign using the specified provider
        return new SignatureWrapper(algorithm, privateKey, provider)
                .update(dataToBeSigned)
                .sign();      
    }

    static void rejectPossibleKeyId(CBORObject optionalKeyId) throws GeneralSecurityException {
        if (optionalKeyId != null) {
            throw new GeneralSecurityException(STDERR_KEY_ID_PUBLIC);
        }
    }
    
    /**
     * For internal use only
     */
    static final String STDERR_KEY_ID_PUBLIC = 
            "\"keyId\" cannot be combined with public key objects";

}
