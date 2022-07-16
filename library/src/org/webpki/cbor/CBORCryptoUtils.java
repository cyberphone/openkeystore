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
import org.webpki.crypto.KeyAlgorithms;
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
         * See {@link CBORCryptoUtils#unwrapContainerMap(CBORObject, POLICY tagPolicy)} for details
         * on the syntax for wrapped maps.
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
     * Policy regarding additional CSF and CEF features.
     */
    public static enum POLICY {FORBIDDEN, OPTIONAL, MANDATORY}
    
    static void inputError(String text, POLICY policy) throws IOException {
        CBORObject.reportError(String.format("%s. Policy: %s", text, policy.toString()));
    }
 
    /**
     * Unwraps a container map object.
 
     * <p>
     * This method is intended for CBOR <code>map</code> objects that <i>optionally</i>
     * are wrapped in a tag.  This implementation accepts two variants of tags:
     * </p>
     * <code>&nbsp;&nbsp;&nbsp;&nbsp;nnn(</code><i>CBOR&nbsp;map</i><code>)</code><br>
     * <code>&nbsp;&nbsp;&nbsp;&nbsp;nnn([</code><i>CBOR&nbsp;text&nbsp;string</i><code>,&nbsp;</code><i>CBOR&nbsp;map</i><code>])</code>
     * <p>
     * The purpose of the second construct is to provide a
     * generic way of adding an object type identifier in the
     * form of a URL to CBOR <code>map</code> objects.
     * The CBOR tag (<code>nnn</code>) would in this case be <i>constant</i>. 
     * Example:
     * </p>
     * <pre>
     *     211(["https://example.com/myobject", {
     *       "amount": "145.00",
     *       "currency": "USD"
     *     }])</pre><p>
     * Both wrapping methods are intrinsically
     * supported by {@link CBORValidator} and
     * {@link CBORDecrypter}
     * for signatures and encryption respectively.
     * </p>
     * <p>
     * To enable the <i>creation</i> of wrapped data you must implement
     * {@link Intercepter#wrap(CBORMap)}.
     * </p>
     * 
     * @param container A map optionally enclosed in a tag 
     * @param tagPolicy Tagging policy 
     * @return The map object without the tag
     * @throws IOException
     */
    public static CBORMap unwrapContainerMap(CBORObject container, POLICY tagPolicy)
            throws IOException {
        if (container.getType() == CBORTypes.TAG) {
            if (tagPolicy == POLICY.FORBIDDEN) {
                inputError("Tag encountered", tagPolicy);
            }
            CBORObject tagged = container.getTag().getObject();;
            if (tagged.getType() == CBORTypes.ARRAY) {
                CBORArray holder = tagged.getArray();
                if (holder.size() != 2 ||
                    holder.getObject(0).getType() != CBORTypes.TEXT_STRING) {
                    CBORObject.reportError("Tag syntax nnn([\"string\", {}]) expected");
                }
                container = holder.getObject(1);
            } else container = tagged;
        } else if (tagPolicy == POLICY.MANDATORY) {
            inputError("Missing tag", tagPolicy);
        }
        return container.getMap();
    }
    
    static CBORObject getOptionalKeyId(CBORMap holderMap) throws IOException {

        // Get the key Id if there is one and scan() to make sure checkForUnread() won't fail
        return holderMap.hasKey(KEY_ID_LABEL) ?
            holderMap.getObject(KEY_ID_LABEL).scan() : null;
    }
    
    static void scanCustomData(CBORMap holderMap, POLICY customDataPolicy) throws IOException {
 
        // Access a possible customData element in order satisfy checkForUnread().
        if (holderMap.hasKey(CUSTOM_DATA_LABEL)) {
            if (customDataPolicy == POLICY.FORBIDDEN) {
                inputError("Custom data encountered", customDataPolicy);
            }
            holderMap.getObject(CUSTOM_DATA_LABEL).scan();
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
