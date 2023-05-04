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
package org.webpki.crypto;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;

import java.security.interfaces.ECKey;

import java.security.spec.ECParameterSpec;
//#if !ANDROID
import java.security.spec.PSSParameterSpec;
//#endif

//#if ANDROID
// Source configured for Android. 
//#else
//#if BOUNCYCASTLE
// Source configured for the BouncyCastle provider.
//#else 
// Source configured for JDK.
//#endif
//#endif

/**
 * Wrapper over {@link java.security.Signature}.
 */ 
public class SignatureWrapper {

    static final int ASN1_SEQUENCE = 0x30;
    static final int ASN1_INTEGER  = 0x02;

    static final int LEADING_ZERO  = 0x00;

    boolean ecdsaAsn1EncodedFlag;

    private static int getExtendTo(ECParameterSpec ecParameters) {
        return (KeyAlgorithms.getECKeyAlgorithm(ecParameters).getPublicKeySizeInBits() + 7) / 8;
    }

    private byte[] decodeAsn1EncodedEcdsaSignature(byte[] derCodedSignature,
                                                   ECParameterSpec ecParameters) {
        int extendTo = getExtendTo(ecParameters);
        int index = 2;
        int length;
        byte[] concatenatedSignature = new byte[extendTo << 1];
        if (derCodedSignature[0] != ASN1_SEQUENCE) {
            throw new CryptoException("Not SEQUENCE");
        }
        length = derCodedSignature[1];
        if (length < 4) {
            if (length != -127) {
                throw new CryptoException("ASN.1 Length error");
            }
            length = derCodedSignature[index++] & 0xFF;
        }
        if (index != derCodedSignature.length - length) {
            throw new CryptoException("ASN.1 Length error");
        }
        for (int offset = 0; offset <= extendTo; offset += extendTo) {
            if (derCodedSignature[index++] != ASN1_INTEGER) {
                throw new CryptoException("Not INTEGER");
            }
            int l = derCodedSignature[index++];
            while (l > extendTo) {
                if (derCodedSignature[index++] != LEADING_ZERO) {
                    throw new CryptoException("Bad INTEGER");
                }
                l--;
            }
            System.arraycopy(derCodedSignature, index, concatenatedSignature, offset + extendTo - l, l);
            index += l;
        }
        if (index != derCodedSignature.length) {
            throw new CryptoException("ASN.1 Length error");
        }
        return concatenatedSignature;
    }

    private byte[] encodeAsn1EncodedEcdsaSignature(byte[] concatenatedSignature,
                                                   ECParameterSpec ecParameters) {
        int extendTo = getExtendTo(ecParameters);
        if (extendTo != concatenatedSignature.length / 2) {
            throw new CryptoException("Signature length error");
        }

        int i = extendTo;
        while (i > 0 && concatenatedSignature[extendTo - i] == LEADING_ZERO) {
            i--;
        }
        int j = i;
        if (concatenatedSignature[extendTo - i] < 0) {
            j++;
        }

        int k = extendTo;
        while (k > 0 && concatenatedSignature[2 * extendTo - k] == LEADING_ZERO) {
            k--;
        }
        int l = k;
        if (concatenatedSignature[2 * extendTo - k] < 0) {
            l++;
        }

        int len = 2 + j + 2 + l;
        int offset = 1;
        byte derCodedSignature[];
        if (len < 128) {
            derCodedSignature = new byte[len + 2];
        } else {
            derCodedSignature = new byte[len + 3];
            derCodedSignature[1] = (byte) 0x81;
            offset = 2;
        }
        derCodedSignature[0] = ASN1_SEQUENCE;
        derCodedSignature[offset++] = (byte) len;
        derCodedSignature[offset++] = ASN1_INTEGER;
        derCodedSignature[offset++] = (byte) j;
        System.arraycopy(concatenatedSignature, extendTo - i, derCodedSignature, offset + j - i, i);
        offset += j;
        derCodedSignature[offset++] = ASN1_INTEGER;
        derCodedSignature[offset++] = (byte) l;
        System.arraycopy(concatenatedSignature, 2 * extendTo - k, derCodedSignature, offset + l - k, k);
        return derCodedSignature;
    }

    Signature instance;
    boolean unmodifiedSignature;
    ECParameterSpec ecParameters;

    private SignatureWrapper(AsymSignatureAlgorithms algorithm, String provider, Key key) 
            throws GeneralSecurityException {
        KeyAlgorithms keyAlgorithm = KeyAlgorithms.getKeyAlgorithm(key);
        if (keyAlgorithm.getKeyType() != algorithm.getKeyType()) {
            throw new CryptoException(
                    "Supplied key (" +
                    keyAlgorithm.toString() +
                    ") is incompatible with specified algorithm (" +
                    algorithm.toString() +
                    ")");
        }
//#if BOUNCYCASTLE
        if (provider == null) {
            instance = algorithm.getKeyType() == KeyTypes.EDDSA ?
                    Signature.getInstance(algorithm.getJceName(), "BC")
                                             : 
                    Signature.getInstance(algorithm.getJceName());
        } else {
            instance = Signature.getInstance(algorithm.getJceName(), provider);
        }
//#else
        instance = provider == null ? 
                Signature.getInstance(algorithm.getJceName())
                                    :
                Signature.getInstance(algorithm.getJceName(), provider);
//#endif
        unmodifiedSignature = algorithm.getKeyType() != KeyTypes.EC;
//#if ANDROID
        if (!unmodifiedSignature) {
//#else
        if (unmodifiedSignature) {
            if (algorithm.getMGF1ParameterSpec() != null) {
                instance.setParameter(
                        new PSSParameterSpec(algorithm.getDigestAlgorithm().getJceName(),
                                             "MGF1", 
                                             algorithm.getMGF1ParameterSpec(), 
                                             algorithm.getDigestAlgorithm().getResultBytes(),
                                             1));
            }
        } else {
//#endif
            ecParameters = ((ECKey) key).getParams();
        }
    }

    /**
     * Initiates a verifier.
     * @param algorithm
     * @param publicKey
     * @param provider
     * @throws GeneralSecurityException
     */
    public SignatureWrapper(AsymSignatureAlgorithms algorithm, 
                            PublicKey publicKey,
                            String provider) throws GeneralSecurityException {
        this(algorithm, provider, publicKey);
        instance.initVerify(publicKey);
    }

    /**
     * Initiates a verifier.
     * @param algorithm
     * @param publicKey
     * @throws GeneralSecurityException
     */
    public SignatureWrapper(AsymSignatureAlgorithms algorithm,
                            PublicKey publicKey) throws GeneralSecurityException {
        this(algorithm, publicKey, null);
    }

    /**
     * Initites a signer.
     * @param algorithm
     * @param privateKey
     * @param provider
     * @throws GeneralSecurityException
     */
    public SignatureWrapper(AsymSignatureAlgorithms algorithm,
                            PrivateKey privateKey,
                            String provider) throws GeneralSecurityException {
        this(algorithm, provider, privateKey);
        instance.initSign(privateKey);
    }

    /**
     * Initiates a signer.
     * @param algorithm
     * @param privateKey
     * @throws GeneralSecurityException
     */
    public SignatureWrapper(AsymSignatureAlgorithms algorithm,
                            PrivateKey privateKey) throws GeneralSecurityException {
        this(algorithm, privateKey, null);
    }

    /**
     * Sets ASN.1 encoding mode for ECDSA.
     * <p>
     * Default is <code>false</code>.
     * </p>
     * @param flag
     * @return
     */
    public SignatureWrapper ecdsaAsn1SignatureEncoding(boolean flag) {
        ecdsaAsn1EncodedFlag = flag;
        return this;
    }

    /**
     * See {@link java.security.Signature}.
     * 
     * @param data
     * @return
     * @throws GeneralSecurityException
     */
    public SignatureWrapper update(byte[] data) throws GeneralSecurityException {
        instance.update(data);
        return this;
    }

    /**
     * See {@link java.security.Signature}.
     * 
     * @param data
     * @return
     * @throws GeneralSecurityException
     */
    public SignatureWrapper update(byte data) throws GeneralSecurityException {
        instance.update(data);
        return this;
    }

    public Provider getProvider() {
        return instance.getProvider();
    }

    /**
     * See {@link java.security.Signature}.
     * 
     * @param signature
     * @return
     * @throws GeneralSecurityException
     */
    public boolean verify(byte[] signature) throws GeneralSecurityException {
        return instance.verify(ecdsaAsn1EncodedFlag || unmodifiedSignature ?
                signature : encodeAsn1EncodedEcdsaSignature(signature, ecParameters));
    }

    /**
     * See {@link java.security.Signature}.
     * 
     * @return
     * @throws GeneralSecurityException
     */
    public byte[] sign() throws GeneralSecurityException {
        return ecdsaAsn1EncodedFlag || unmodifiedSignature ?
                instance.sign() : decodeAsn1EncodedEcdsaSignature(instance.sign(), ecParameters);
    }
    
    /**
     * Signature creation conveniance method.
     * <p>
     * This method generates JOSE/COSE compatible signatures.
     * </p>
     * <p>
     * For security related errors, {@link CryptoException} is thrown.
     * </p> 
     * 
     * @param privateKey Signature key
     * @param algorithm Signature algorithm
     * @param data Data to sign
     * @param provider Optional provider or <code>null</code>
     * @return Signature
     */
    public static byte[] sign(PrivateKey privateKey,
                              AsymSignatureAlgorithms algorithm,
                              byte[] data,
                              String provider) {
        try {
            return new SignatureWrapper(algorithm, privateKey, provider)
                           .update(data)
                           .sign();
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        }
    }
    
    /**
     * Signature validation conveniance method.
     * <p>
     * This method validates JOSE/COSE compatible signatures.
     * </p>
     * <p>
     * For security related errors including invalid signatures, {@link CryptoException} is thrown.
     * </p> 
     * 
     * @param publicKey Validtion key
     * @param algorithm Signature algorithm
     * @param data The data what was signed
     * @param signature The signature to be validated
     * @param provider Optional provider or <code>null</code>
     */
    public static void validate(PublicKey publicKey,
                                AsymSignatureAlgorithms algorithm,
                                byte[] data,
                                byte[] signature,
                                String provider) {
        try {
            if (!new SignatureWrapper(algorithm, publicKey, provider)
                         .update(data)
                         .verify(signature)) {
                throw new CryptoException("Bad signature for key: " + publicKey.toString());
            }
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        }
    }
}
