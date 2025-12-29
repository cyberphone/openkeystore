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

import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.util.ArrayList;

import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.CryptoException;
import org.webpki.crypto.EncryptionCore;
import org.webpki.crypto.KeyEncryptionAlgorithms;

import static org.webpki.cbor.CBORCryptoConstants.*;

import static org.webpki.cbor.CBORInternal.*;

/**
 * Class holding CBOR crypto support.
 */
public class CBORCryptoUtils {
    
    private CBORCryptoUtils() {}
    
    /**
     * Decode a certificate path from a CBOR array.
     *<p>
     * The CBOR array is assumed to hold one or more X.509 certificates in DER format,
     * each encoded as a CBOR <code>byte&nbsp;string</code>. 
     * Note that the certificates must be featured in <i>ascending order</i>
     * with respect to parenthood.  That is,
     * the certificate at index <code>0</code> would normally be
     * an end-entity certificate.
     * </p>
     * <p>
     * See also {@link #encodeCertificateArray(X509Certificate[])}.
     * </p>
     * 
     * @param array CBOR array with X.509 certificates
     * @return Decoded X.509 certificate path
     */
    public static X509Certificate[] decodeCertificateArray(CBORArray array) {
        ArrayList<byte[]> blobs = new ArrayList<>();
        int index = 0;
        do {
            blobs.add(array.objects.get(index).getBytes());
        } while (++index < array.objects.size());
        return CertificateUtil.makeCertificatePath(blobs);
    }

    /**
     * Encode certificate path into a CBOR array.
     * <p>
     * Note that the certificates must be featured in <i>ascending order</i>
     * with respect to parenthood.  That is,
     * the certificate at index <code>0</code> would normally be
     * an end-entity certificate.  The CBOR array
     * will after processing hold a list of
     * DER-encoded certificates, each represented by a CBOR
     * <code>byte&nbsp;string</code>.
     * </p>
     * <p>
     * See also {@link #decodeCertificateArray(CBORArray)}.
     * </p>
     * 
     * @param certificatePath X.509 certificate path to be encoded 
     * @return CBOR array with X.509 certificates
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
         * Optionally add custom data to the map.
         * <p>
         * Custom data may be any valid CBOR object.  This data is assigned
         * to the CSF/CEF specific label {@link CBORCryptoConstants#CXF_CUSTOM_DATA_LBL}.
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
         * Get tag or custom data.
         * 
         * @param objectOrNull If there is no tag or custom data this argument is <code>null</code>
         *
         */
        void foundData(CBORObject objectOrNull);
    }
    
    /**
     * Policy regarding additional CSF and CEF features.
     */
    public enum POLICY {FORBIDDEN, OPTIONAL, MANDATORY}
    
    private static void inputError(String text, POLICY policy) {
        cborError("%s. Policy: %s", text, policy.toString());
    }
 
    static CBORMap unwrapContainerMap(CBORObject container, 
                                      POLICY tagPolicy,
                                      Collector callBackOrNull) {
        if (container instanceof CBORTag) {
            if (tagPolicy == POLICY.FORBIDDEN) {
                inputError("Tag encountered", tagPolicy);
            }
            // Do NOT replace this with a tag in instanceof!
            CBORTag tag = container.getTag();
            container = tag.object;
            if (tag.cotxObject != null) {
                container = tag.cotxObject.object;
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
        return holderMap.containsKey(CXF_KEY_ID_LBL) ?
            holderMap.get(CXF_KEY_ID_LBL).scan() : null;
    }
    
    static void getCustomData(CBORMap holderMap, 
                              POLICY customDataPolicy,
                              Collector callBackOrNull) {
        // Get optional customData element.
        if (holderMap.containsKey(CXF_CUSTOM_DATA_LBL)) {
            if (customDataPolicy == POLICY.FORBIDDEN) {
                inputError("Custom data encountered", customDataPolicy);
            }
            // It is OK to not read customData during validation.
            CBORObject customData = holderMap.get(CXF_CUSTOM_DATA_LBL).scan();
            if (callBackOrNull != null) {
                callBackOrNull.foundData(customData);
            }
        } else if (customDataPolicy == POLICY.MANDATORY) {
            inputError("Missing custom data", customDataPolicy);
        }
    }
    
    static byte[] commonKeyEncryption(PublicKey publicKey,
                                      CBORMap keyEncryption,
                                      KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                      ContentEncryptionAlgorithms contentEncryptionAlgorithm) {

        // The mandatory key encryption algorithm
        keyEncryption.set(CXF_ALGORITHM_LBL,
                          new CBORInt(keyEncryptionAlgorithm.getCoseAlgorithmId()));
        
        // The sole cryptographic operation 
        EncryptionCore.AsymmetricEncryptionResult result = EncryptionCore.encryptKey(
                                    true,
                                    publicKey, 
                                    keyEncryptionAlgorithm, 
                                    contentEncryptionAlgorithm);

        if (!keyEncryptionAlgorithm.isRsa()) {
            // ECDH-ES requires the ephemeral public key
            keyEncryption.set(CEF_EPHEMERAL_KEY_LBL,
                              CBORPublicKey.convert(result.getEphemeralKey()));
        }
        if (keyEncryptionAlgorithm.isKeyWrap()) {
            // Encrypted key
            keyEncryption.set(CEF_CIPHER_TEXT_LBL, new CBORBytes(result.getEncryptedKey()));
        }
        return result.getContentEncryptionKey();
    }
    
    static byte[] getEncryptedKey(CBORMap innerObject,
                                  KeyEncryptionAlgorithms keyEncryptionAlgorithm) {
        return keyEncryptionAlgorithm.isKeyWrap() ?  // All but ECDH-ES
            innerObject.get(CEF_CIPHER_TEXT_LBL).getBytes() : null;
    }
    
    static PublicKey getEphemeralKey(CBORMap innerObject,
                                     KeyEncryptionAlgorithms keyEncryptionAlgorithm) {
        return keyEncryptionAlgorithm.isRsa() ? null :
            CBORPublicKey.convert(innerObject.get(CEF_EPHEMERAL_KEY_LBL));
        
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
