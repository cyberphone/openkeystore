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
package org.webpki.crypto;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;

import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

import java.security.spec.ECParameterSpec;

/**
 * Wrapper over java.security.Signature
 */
public class SignatureWrapper {

    static final int ASN1_SEQUENCE = 0x30;
    static final int ASN1_INTEGER  = 0x02;

    static final int LEADING_ZERO  = 0x00;

    boolean ecdsaDerEncoded;

    private static int getExtendTo(ECParameterSpec ecParameters) throws IOException {
        return (KeyAlgorithms.getECKeyAlgorithm(ecParameters).getPublicKeySizeInBits() + 7) / 8;
    }

    public static byte[] decodeDEREncodedECDSASignature(byte[] derCodedSignature,
                                                        ECParameterSpec ecParameters) throws IOException {
        int extendTo = getExtendTo(ecParameters);
        int index = 2;
        int length;
        byte[] concatenatedSignature = new byte[extendTo << 1];
        if (derCodedSignature[0] != ASN1_SEQUENCE) {
            throw new IOException("Not SEQUENCE");
        }
        length = derCodedSignature[1];
        if (length < 4) {
            if (length != -127) {
                throw new IOException("ASN.1 Length error");
            }
            length = derCodedSignature[index++] & 0xFF;
        }
        if (index != derCodedSignature.length - length) {
            throw new IOException("ASN.1 Length error");
        }
        for (int offset = 0; offset <= extendTo; offset += extendTo) {
            if (derCodedSignature[index++] != ASN1_INTEGER) {
                throw new IOException("Not INTEGER");
            }
            int l = derCodedSignature[index++];
            while (l > extendTo) {
                if (derCodedSignature[index++] != LEADING_ZERO) {
                    throw new IOException("Bad INTEGER");
                }
                l--;
            }
            System.arraycopy(derCodedSignature, index, concatenatedSignature, offset + extendTo - l, l);
            index += l;
        }
        if (index != derCodedSignature.length) {
            throw new IOException("ASN.1 Length error");
        }
        return concatenatedSignature;
    }

    public static byte[] encodeDEREncodedECDSASignature(byte[] concatenatedSignature,
                                                        ECParameterSpec ecParameters) throws IOException {
        int extendTo = getExtendTo(ecParameters);
        if (extendTo != concatenatedSignature.length / 2) {
            throw new IOException("Signature length error");
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
    boolean rsaFlag;
    ECParameterSpec ecParameters;

    private SignatureWrapper(AsymSignatureAlgorithms algorithm, String provider, Key key) throws GeneralSecurityException, IOException {
        instance = provider == null ? Signature.getInstance(algorithm.getJceName())
                                                    : 
                                      Signature.getInstance(algorithm.getJceName(), provider);
        rsaFlag = key instanceof RSAKey;
        if (!rsaFlag) {
            ecParameters = ((ECKey) key).getParams();
        }
    }

    public SignatureWrapper(AsymSignatureAlgorithms algorithm, 
                            PublicKey publicKey,
                            String provider) throws GeneralSecurityException, IOException {
        this(algorithm, provider, publicKey);
        instance.initVerify(publicKey);
    }

    public SignatureWrapper(AsymSignatureAlgorithms algorithm,
                            PublicKey publicKey) throws GeneralSecurityException, IOException {
        this(algorithm, publicKey, null);
    }

    public SignatureWrapper(AsymSignatureAlgorithms algorithm,
                            PrivateKey privateKey,
                            String provider) throws GeneralSecurityException, IOException {
        this(algorithm, provider, privateKey);
        instance.initSign(privateKey);
    }

    public SignatureWrapper(AsymSignatureAlgorithms algorithm,
                            PrivateKey privateKey) throws GeneralSecurityException, IOException {
        this(algorithm, privateKey, null);
    }

    public SignatureWrapper setEcdsaSignatureEncoding(boolean derEncoded) {
        ecdsaDerEncoded = derEncoded;
        return this;
    }

    public SignatureWrapper update(byte[] data) throws GeneralSecurityException {
        instance.update(data);
        return this;
    }

    public SignatureWrapper update(byte data) throws GeneralSecurityException {
        instance.update(data);
        return this;
    }

    public Provider getProvider() {
        return instance.getProvider();
    }

    public boolean verify(byte[] signature) throws GeneralSecurityException, IOException {
        return instance.verify(ecdsaDerEncoded || rsaFlag ?
                signature : SignatureWrapper.encodeDEREncodedECDSASignature(signature, ecParameters));
    }

    public byte[] sign() throws GeneralSecurityException, IOException {
        return ecdsaDerEncoded || rsaFlag ?
                instance.sign() : SignatureWrapper.decodeDEREncodedECDSASignature(instance.sign(), ecParameters);
    }
}
