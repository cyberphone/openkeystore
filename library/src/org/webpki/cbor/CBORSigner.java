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
import java.util.HashMap;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.HmacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

/**
 * Base class for creating CBOR signatures.
 */
public abstract class CBORSigner {

    public static final CBORInteger ALGORITHM_LABEL  = new CBORInteger(1);
    public static final CBORInteger PUBLIC_KEY_LABEL = new CBORInteger(2);
    public static final CBORInteger KEY_ID_LABEL     = new CBORInteger(3);
    public static final CBORInteger CERT_PATH_LABEL  = new CBORInteger(4);
    public static final CBORInteger SIGNATURE_LABEL  = new CBORInteger(5);
    
    
    static final HashMap<SignatureAlgorithms, Integer> WEBPKI_2_CBOR_ALG = new HashMap<>();
    
    static {
        // COSE compatible
        WEBPKI_2_CBOR_ALG.put(AsymSignatureAlgorithms.ECDSA_SHA256,   -7);
        WEBPKI_2_CBOR_ALG.put(AsymSignatureAlgorithms.ECDSA_SHA384,  -35);
        WEBPKI_2_CBOR_ALG.put(AsymSignatureAlgorithms.ECDSA_SHA512,  -36);
        WEBPKI_2_CBOR_ALG.put(AsymSignatureAlgorithms.RSAPSS_SHA256, -37);
        WEBPKI_2_CBOR_ALG.put(AsymSignatureAlgorithms.RSAPSS_SHA384, -38);
        WEBPKI_2_CBOR_ALG.put(AsymSignatureAlgorithms.RSAPSS_SHA512, -39);
        WEBPKI_2_CBOR_ALG.put(HmacAlgorithms.HMAC_SHA256,              5);
        WEBPKI_2_CBOR_ALG.put(HmacAlgorithms.HMAC_SHA384,              6);
        WEBPKI_2_CBOR_ALG.put(HmacAlgorithms.HMAC_SHA512,              7);
                              
        // Incompatible with COSE, but compatible with most cryptographic
        // APIs as well as PKIX's way of dealing with with different EdDSA
        // variants.  That is, each being treated as a specific algorithm.
        WEBPKI_2_CBOR_ALG.put(AsymSignatureAlgorithms.ED25519,        -9);
        WEBPKI_2_CBOR_ALG.put(AsymSignatureAlgorithms.ED448,         -10);
        
        // Not supported by COSE, but RS256 was added by FIDO and the
        // other PKCS 1.5 variants may very well follow
        WEBPKI_2_CBOR_ALG.put(AsymSignatureAlgorithms.RSA_SHA256,    -257);
        WEBPKI_2_CBOR_ALG.put(AsymSignatureAlgorithms.RSA_SHA384,    -258);
        WEBPKI_2_CBOR_ALG.put(AsymSignatureAlgorithms.RSA_SHA512,    -259);
    }

    static final HashMap<Integer, SignatureAlgorithms> CBOR_2_WEBPKI_ALG = new HashMap<>();

    static {
        for (SignatureAlgorithms key : WEBPKI_2_CBOR_ALG.keySet()) {
            CBOR_2_WEBPKI_ALG.put(WEBPKI_2_CBOR_ALG.get(key), key);
        }
    }
    
    static SignatureAlgorithms getSignatureAlgorithm(int cborSignatureAlgorithm, 
                                                     boolean publicKey)                                      
        throws GeneralSecurityException {
        
        SignatureAlgorithms signatureAlgorithms = CBOR_2_WEBPKI_ALG.get(cborSignatureAlgorithm);
        if (signatureAlgorithms ==  null) {
            throw new GeneralSecurityException("Unknown algorithm: " + cborSignatureAlgorithm);
        }
        if (signatureAlgorithms.isSymmetric() ^ publicKey) {
            
        }
        return signatureAlgorithms;
    }
    
    // Set by implementing classes
    String provider;
    
    PublicKey publicKey;
    
    int algorithmId;
    
    // Optional key ID
    String keyId;

    CBORSigner() {}
    
    abstract byte[] signData(byte[] dataToSign) throws GeneralSecurityException, IOException;
    
    /**
     * Set signature key Id.
     * 
     * In the case the public key is not provided in the signature
     * object, the signature key may be tied to an identifier
     * known by the relying party.  How such an identifier
     * is used to retrieve the proper public key is up to a
     * convention between the parties using
     * a specific message scheme.  A keyId may be a database
     * index or a hash of the public key.  It may also be a
     * URL pointing to a Web server holding a public key in
     * PEM format.
     * <p>
     * For HMAC-signatures, a keyId or implicit key are
     * the only ways to retrieve the proper secret key.
     * </p>
     * 
     * @param keyId A keId string
     * @return this
     */
    public CBORSigner setKeyId(String keyId) {
        this.keyId = keyId;
        return this;
    }

    void sign(CBORObject key, CBORMapBase objectToSign) throws IOException, 
                                                               GeneralSecurityException {
        // Create empty signature object.
        CBORMapBase signatureObject = new CBORIntegerMap();
        
        // Add the mandatory signature algorithm.
        signatureObject.setObject(ALGORITHM_LABEL, new CBORInteger(algorithmId));
        
        // If a public key has been defined, add it to the signature object.
        if (publicKey != null) {
            signatureObject.setObject(PUBLIC_KEY_LABEL, 
                                      CBORPublicKey.encodePublicKey(publicKey));
        }

        // Add a keyId if there is one.
        if (keyId != null) {
            signatureObject.setObject(KEY_ID_LABEL, new CBORTextString(keyId));
        }

        // Add the prepared signature object to the object we want to sign. 
        objectToSign.setObject(key, signatureObject);

        // Finally, sign all but the signature label and associated value.
        // encode() is supposed to produce a deterministic representation.
        signatureObject.keys.put(SIGNATURE_LABEL, 
                                 new CBORByteString(signData(objectToSign.encode())));
    }
}
