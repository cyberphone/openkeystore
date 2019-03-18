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
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SecureRandom;

import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

import java.security.spec.ECParameterSpec;

import org.webpki.json.JSONCryptoHelper;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONSignatureDecoder;

import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.SignatureWrapper;

/**
 * Wrapper over java.security.Signature
 */
public class DeterministicSignatureWrapper {

    boolean ecdsaDerEncoded;
    
    // https://tools.ietf.org/rfc/rfc4754.txt
    // "k"
    static String FIX_RANDOM = "9E56F509196784D963D1C0A401510EE7ADA3DCC5DEE04B154BF61AF1D5A6DECE";
    
    // "w"
    static String PRIVATE_KEY = "DC51D3866A15BACDE33D96F992FCA99DA7E6EF0934E7097559C27F1614C88A7F";
    
    static String PUBLIC_X = "2442A5CC0ECD015FA3CA31DC8E2BBC70BF42D60CBCA20085E0822CB04235E970";

    static String PUBLIC_Y = "6FC98BD7E50211A4A27102FA3549DF79EBCB4BF246B80945CDDFE7D509BBFD7D";
    
    static byte[] INPUT = { 0x61, 0x62, 0x63 };
    
    static String RESULT = "CB28E0999B9C7715FD0A80D8E47A77079716CBBF917DD72E97566EA1C066957C86FA3BB4E26CAD5BF90B7F81899256CE7594BB1EA0C89212748BFF3B3D5B0315";

    
    public static class FixedSecureRandom extends SecureRandom {
        private static final long serialVersionUID = 1L;
        public FixedSecureRandom() { }
        private int nextBytesIndex = 0;

        private byte[] nextBytesValues = null;

        public void setBytes(byte[] values) {
            this.nextBytesValues = values; 
        }

        public void nextBytes(byte[] b) {
            if (nextBytesValues==null) { 
                super.nextBytes(b);
            } else if (nextBytesValues.length==0) { 
                super.nextBytes(b);
            } else {
                for (int i=0; i<b.length; i++) {
                    b[i] = nextBytesValues[nextBytesIndex];
                    nextBytesIndex = (nextBytesIndex + 1) % nextBytesValues.length;
                }
            }
        }
    }
    
    Signature instance;
    boolean rsaFlag;
    ECParameterSpec ecParameters;

    private DeterministicSignatureWrapper(AsymSignatureAlgorithms algorithm, String provider, Key key) throws GeneralSecurityException, IOException {
        instance = provider == null ? Signature.getInstance(algorithm.getJceName())
                                                    : 
                                      Signature.getInstance(algorithm.getJceName(), provider);
        rsaFlag = key instanceof RSAKey;
        if (!rsaFlag) {
            ecParameters = ((ECKey) key).getParams();
        }
    }

    public DeterministicSignatureWrapper(AsymSignatureAlgorithms algorithm, 
                            PublicKey publicKey,
                            String provider) throws GeneralSecurityException, IOException {
        this(algorithm, provider, publicKey);
        instance.initVerify(publicKey);
    }

    public DeterministicSignatureWrapper(AsymSignatureAlgorithms algorithm,
                            PublicKey publicKey) throws GeneralSecurityException, IOException {
        this(algorithm, publicKey, null);
    }

    public DeterministicSignatureWrapper(AsymSignatureAlgorithms algorithm,
                            PrivateKey privateKey,
                            String provider) throws GeneralSecurityException, IOException {
        this(algorithm, provider, privateKey);
        FixedSecureRandom random = new FixedSecureRandom();
        random.setBytes(DebugFormatter.getByteArrayFromHex(FIX_RANDOM));
        instance.initSign(privateKey, random);
    }

    public DeterministicSignatureWrapper(AsymSignatureAlgorithms algorithm,
                            PrivateKey privateKey) throws GeneralSecurityException, IOException {
        this(algorithm, privateKey, null);
    }

    public DeterministicSignatureWrapper setECDSASignatureEncoding(boolean derEncoded) {
        ecdsaDerEncoded = derEncoded;
        return this;
    }

    public DeterministicSignatureWrapper update(byte[] data) throws GeneralSecurityException {
        instance.update(data);
        return this;
    }

    public DeterministicSignatureWrapper update(byte data) throws GeneralSecurityException {
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
    
    public static void rfc4754() throws Exception {
        JSONObjectWriter jwk = new JSONObjectWriter()
            .setString(JSONCryptoHelper.KTY_JSON, JSONCryptoHelper.EC_PUBLIC_KEY)
            .setString(JSONCryptoHelper.CRV_JSON,"P-256")
            .setBinary("d", DebugFormatter.getByteArrayFromHex(PRIVATE_KEY))
            .setBinary(JSONCryptoHelper.X_JSON, DebugFormatter.getByteArrayFromHex(PUBLIC_X))
            .setBinary(JSONCryptoHelper.Y_JSON, DebugFormatter.getByteArrayFromHex(PUBLIC_Y));
        KeyPair keyPair = JSONParser.parse(jwk.toString()).getKeyPair();
        byte[] signature = new DeterministicSignatureWrapper(AsymSignatureAlgorithms.ECDSA_SHA256,
                                                             keyPair.getPrivate())
            .update(INPUT)
            .sign();
        if (!ArrayUtil.compare(signature, DebugFormatter.getByteArrayFromHex(RESULT))) {
            throw new IOException("Unexpected signature");
        }
        if (!new DeterministicSignatureWrapper(AsymSignatureAlgorithms.ECDSA_SHA256,
                                               keyPair.getPublic())
                .update(INPUT)
                .verify(signature)) {
            throw new IOException("Didn't verify");
        }
    }
    
    public static void main(String[] argc) {
        try {
            CustomCryptoProvider.forcedLoad(true);
            rfc4754();
            System.out.println("Success!");
        } catch (Exception e) {
            e.printStackTrace();
        }
        
    }
}
