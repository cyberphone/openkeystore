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

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Base class for creating CBOR signatures.
 * 
 * It uses COSE algorithms but relies on CSF for the packaging.
 * 
 */
public abstract class CBORSigner {
 
    // Set by implementing classes
    String provider;
    
    int coseAlgorithmId;
    
    // Optional key ID
    CBORObject optionalKeyId;

    CBORSigner() {}
    
    abstract byte[] signData(byte[] dataToSign) throws IOException, GeneralSecurityException;
    
    abstract void additionalItems(CBORMap signatureObject)
            throws IOException, GeneralSecurityException;
    
    /**
     * Sets signature <code>keyId</code>.
     * 
     * In the case the public key is not provided in the signature
     * object, the signature key may be tied to an identifier
     * known by the relying party.  How such an identifier
     * is used to retrieve the proper public key is up to a
     * convention between the parties using
     * a specific message scheme.  A <code>keyId</code> may be a
     * database index, a hash of the public key, a text string,
     * or a URL pointing to a Web server holding a public key
     * in PEM format.
     * <p>
     * For HMAC-signatures, a <code>keyId</code> or implicit key are
     * the only ways to retrieve the proper secret key.
     * </p>
     * <p>
     * Note that <code>keyId</code> is not permitted for X509 based signatures.
     * </p>
     * <p>
     * <p>
     * Note that a <code>keyId</code> argument of <code>null</code> 
     * is equivalent to the default (= no <code>keyId</code>).
     * </p>
     * 
     * @param keyId A CBOR key Id or <code>null</code>
     * @return this
     */
    public CBORSigner setKeyId(CBORObject keyId) {
        this.optionalKeyId = keyId;
        return this;
    }

    /**
     * Sets signature <code>keyId</code>.
     * 
     * The <code>keyId</code> will be represented as a CBOR <code>text&nbsp;string</code>.
     * 
     * @param keyId A CBOR key Id
     * @return this
     * 
     * @see {@link setKeyId(CBORObject)}.
     */
    public CBORSigner setKeyId(String keyId) {
        return setKeyId(new CBORTextString(keyId));
    }

    /**
     * Sets signature <code>keyId</code>.
     * 
     * The <code>keyId</code> will be represented as a CBOR <code>integer</code>.
     * 
     * @param keyId A CBOR key Id
     * @return this
     *
     * @see {@link setKeyId(CBORObject)}.
     */
    public CBORSigner setKeyId(int keyId) {
        return setKeyId(new CBORInteger(keyId));
    }

    /**
     * Sets cryptographic provider.
     * 
     * @param provider Name of provider like "BC"
     * @return CBORSigner
     */
    public CBORSigner setProvider(String provider) {
        this.provider = provider;
        return this;
    }

    /**
     * Signs CBOR object.
     * 
     * @param key Key holding the signature in the CBOR map to sign
     * @param objectToSign CBOR map to be signed
     * @return Signed object
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public CBORMap sign(CBORObject key, CBORMap objectToSign) throws IOException,
                                                                     GeneralSecurityException {

        // Create empty signature object.
        CBORMap signatureObject = new CBORMap();
        
        // Add the mandatory signature algorithm.
        signatureObject.setObject(ALGORITHM_LABEL, new CBORInteger(coseAlgorithmId));
        
        // Add a keyId if there is one.
        if (optionalKeyId != null) {
            signatureObject.setObject(KEY_ID_LABEL, optionalKeyId);
        }
        
        // Asymmetric key signatures add specific items to the signature container.
        additionalItems(signatureObject);
        
        // Add the prepared signature object to the object we want to sign. 
        objectToSign.setObject(key, signatureObject);

        // Finally, sign all but the signature label and associated value.
        // internalEncode() is supposed to produce a deterministic representation.
        signatureObject.keys.put(SIGNATURE_LABEL, 
                                 new CBORByteString(signData(objectToSign.internalEncode())));

        // Return the now signed object.
        return objectToSign;
    }

    /**
     * Signs CBOR object.
     * 
     * @param key Key holding the signature in the CBOR map to sign
     * @param objectToSign CBOR map to be signed
     * @return Signed object
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public CBORMap sign(int key, CBORMap objectToSign) throws IOException,
                                                              GeneralSecurityException {
        return sign(new CBORInteger(key), objectToSign);
    }

    /**
     * Signs CBOR object.
     * 
     * @param key Key holding the signature in the CBOR map to sign
     * @param objectToSign CBOR map to be signed
     * @return Signed object
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public CBORMap sign(String key, CBORMap objectToSign) throws IOException, 
                                                                 GeneralSecurityException {
        return sign(new CBORTextString(key), objectToSign);
    }

    static void checkKeyId(CBORObject optionalKeyId) throws GeneralSecurityException {
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
