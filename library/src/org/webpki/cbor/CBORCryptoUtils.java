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

import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.util.ArrayList;

import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.CryptoException;
import org.webpki.crypto.CryptoRandom;
import org.webpki.crypto.EncryptionCore;
import org.webpki.crypto.KeyEncryptionAlgorithms;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Class holding CBOR crypto support 
 */
public class CBORCryptoUtils {
    
    private CBORCryptoUtils() {}
    
    /**
     * Decodes a certificate path from a CBOR array.
     *<p>
     * Note that the array must only contain a
     * list of X509 certificates in DER format,
     * each encoded as a CBOR <code>byte&nbsp;string</code>. 
     * The certificates must be in ascending
     * order with respect to parenthood.  That is,
     * the first certificate would typically be
     * an end-entity certificate.
     * </p>
     * <p>
     * Also see {@link #encodeCertificateArray(X509Certificate[])}.
     * </p>
     * 
     * @param array CBOR array with X.509 certificates
     * @return Certificate path
     */
    public static X509Certificate[] decodeCertificateArray(CBORArray array) {
        ArrayList<byte[]> blobs = new ArrayList<>();
        int index = 0;
        do {
            blobs.add(array.objectList.get(index).getBytes());
        } while (++index < array.objectList.size());
        return CertificateUtil.makeCertificatePath(blobs);
    }

    /**
     * Encodes certificate path into a CBOR array.
     * <p>
     * Note that the certificates must be in ascending
     * order with respect to parenthood.  That is,
     * the first certificate would typically be
     * an end-entity certificate.  The CBOR array
     * will after the conversion hold a list of
     * DER-encoded certificates, each represented by a CBOR
     * <code>byte&nbsp;string</code>.
     * </p>
     * <p>
     * Also see {@link #decodeCertificateArray(CBORArray)}.
     * </p>
     * 
     * @param certificatePath The certificate path to be converted to CBOR 
     * @return CBORArray
     */
    public static CBORArray encodeCertificateArray(X509Certificate[] certificatePath) {
        CBORArray array = new CBORArray();
        for (X509Certificate cert : CertificateUtil.checkCertificatePath(certificatePath)) {
            array.add(new CBORBytes(CertificateUtil.getBlobFromCertificate(cert)));
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
         * Also see {@link CBORTag} for details on the syntax for wrapped CBOR data.
         * </p>
         * 
         * @param map Unwrapped map
         * @return Original (default implementation) or wrapped map
         */
        default CBORObject wrap(CBORMap map) {
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
         */
        default CBORObject getCustomData() {
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
         */
        void foundData(CBORObject objectOrNull);
    }
    
    /**
     * Policy regarding additional CSF and CEF features.
     */
    public enum POLICY {FORBIDDEN, OPTIONAL, MANDATORY}
    
    static void inputError(String text, POLICY policy) {
        CBORObject.reportError(String.format("%s. Policy: %s", text, policy.toString()));
    }
 
    static CBORMap unwrapContainerMap(CBORObject container, 
                                      POLICY tagPolicy,
                                      Collector callBackOrNull) {
        if (container.getType() == CBORTypes.TAG) {
            if (tagPolicy == POLICY.FORBIDDEN) {
                inputError("Tag encountered", tagPolicy);
            }
            CBORTag tag = container.getTag();
            container = tag.object;
            if (tag.tagNumber == CBORTag.RESERVED_TAG_COTX) {
                container = container.getArray(2).get(1);
            }
            if (callBackOrNull != null) {
                callBackOrNull.foundData(tag);
            }
        } else if (tagPolicy == POLICY.MANDATORY) {
            inputError("Missing tag", tagPolicy);
        }
        return container.getMap();
    }
    
    static CBORObject getKeyId(CBORMap holderMap) {

        // Get the key Id if there is one and scan() to make sure checkForUnread() won't fail
        return holderMap.containsKey(KEY_ID_LABEL) ?
            holderMap.get(KEY_ID_LABEL).scan() : null;
    }
    
    static void getCustomData(CBORMap holderMap, 
                              POLICY customDataPolicy,
                              Collector callBackOrNull) {
        // Get optional customData element.
        if (holderMap.containsKey(CUSTOM_DATA_LABEL)) {
            if (customDataPolicy == POLICY.FORBIDDEN) {
                inputError("Custom data encountered", customDataPolicy);
            }
            // It is OK to not read customData during validation.
            CBORObject customData = holderMap.get(CUSTOM_DATA_LABEL).scan();
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
                                          ContentEncryptionAlgorithms contentEncryptionAlgorithm) {

        // The mandatory key encryption algorithm
        keyEncryption.set(ALGORITHM_LABEL,
                                new CBORInteger(keyEncryptionAlgorithm.getCoseAlgorithmId()));
        
        // Key wrapping algorithms need a key to wrap
        byte[] contentEncryptionKey = keyEncryptionAlgorithm.isKeyWrap() ?
            CryptoRandom.generateRandom(contentEncryptionAlgorithm.getKeyLength()) : null;
                                                                         
        // The core
        EncryptionCore.AsymmetricEncryptionResult result =
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
            keyEncryption.set(EPHEMERAL_KEY_LABEL,
                                    CBORPublicKey.convert(result.getEphemeralKey()));
        }
        if (keyEncryptionAlgorithm.isKeyWrap()) {
            // Encrypted key
            keyEncryption.set(CIPHER_TEXT_LABEL, new CBORBytes(result.getEncryptedKey()));
        }
        return result.getContentEncryptionKey();
    }
    
    static byte[] getEncryptedKey(CBORMap innerObject,
                                  KeyEncryptionAlgorithms keyEncryptionAlgorithm) {
        return keyEncryptionAlgorithm.isKeyWrap() ?  // All but ECDH-ES
            innerObject.get(CIPHER_TEXT_LABEL).getBytes() : null;
    }
    
    static PublicKey getEphemeralKey(CBORMap innerObject,
                                     KeyEncryptionAlgorithms keyEncryptionAlgorithm) {
        return keyEncryptionAlgorithm.isRsa() ? null :
            CBORPublicKey.convert(innerObject.get(EPHEMERAL_KEY_LABEL));
        
    }
    
    static void rejectPossibleKeyId(CBORObject optionalKeyId) {
        if (optionalKeyId != null) {
            throw new CryptoException(STDERR_KEY_ID_PUBLIC);
        }
    }
    
    /**
     * For internal use only
     */
    static final String STDERR_KEY_ID_PUBLIC = 
            "\"keyId\" cannot be combined with public key objects";

}
