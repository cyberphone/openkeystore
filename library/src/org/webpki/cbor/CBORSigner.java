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

import org.webpki.crypto.SignatureAlgorithms;

import static org.webpki.cbor.CBORCryptoConstants.*;

import org.webpki.cbor.CBORCryptoUtils.Intercepter;

/**
 * Base class for signing data.
 * <p>
 * This implementation supports signatures using 
 * <a title='CSF' target='_blank'
 * href='doc-files/signatures.html'>CSF</a>
 * (CBOR Signature Format) packaging, while algorithms are derived from COSE.
 * </p>
 * <p>
 * Note that signer objects may be used any number of times
 * (assuming that the same parameters are valid).  They are also
 * thread-safe.
 * </p>
 * @see CBORValidator
 */
public abstract class CBORSigner {
 
    // The default is to use a map without tagging and custom data.
    Intercepter intercepter = new Intercepter() { };

    // Set by implementing classes
    String provider;
    
    // Optional key ID
    CBORObject optionalKeyId;
    
    private boolean cloneFlag;

    CBORSigner() {}
    
    abstract byte[] coreSigner(byte[] dataToSign);
    
    abstract SignatureAlgorithms getAlgorithm();
    
    abstract void additionalItems(CBORMap signatureObject);
    
    /**
     * Sets optional Intercepter.
     * 
     * @param intercepter An instance of Intercepter
     * @return <code>this</code>
     */
    public CBORSigner setIntercepter(Intercepter intercepter) {
        this.intercepter = intercepter;
        return this;
    }
    
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
     * or a URL pointing to a public key in PEM format.
     * <p>
     * For HMAC-signatures, a <code>keyId</code> or implicit key are
     * the only ways to retrieve the proper secret key.
     * </p>
     * <p>
     * Note that a <code>keyId</code> argument of <code>null</code> 
     * is equivalent to the default (= no <code>keyId</code>).
     * </p>
     * 
     * @param keyId Key Id or <code>null</code>
     * @return <code>this</code>
     */
    public CBORSigner setKeyId(CBORObject keyId) {
        this.optionalKeyId = keyId;
        return this;
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
     * Sets clone mode.
     * <p>
     * By default the {@link #sign(CBORObject, CBORMap)} method
     * <i>overwrites</i> the input <code>map</code> object.
     * </p>
     * 
     * @param flag If <code>true</code> input data will be cloned
     * @return CBORSigner
     */
    public CBORSigner setCloneMode(boolean flag) {
        this.cloneFlag = flag;
        return this;
    }
  
    /**
     * Signs CBOR object.
     * 
     * <p>
     * Adds an enveloped CSF object (signature) to a CBOR map.
     * </p>
     * <p>
     * Also see {@link #setCloneMode(boolean)}.
     * </p>
     * 
     * @param key Key holding the signature in the CBOR map to sign
     * @param mapToSign CBOR map to be signed
     * @return Signed object
     */
    public CBORObject sign(CBORObject key, CBORMap mapToSign) {
        // Signatures update input by default.
        if (cloneFlag) {
            mapToSign = (CBORMap)mapToSign.clone();
        }

        // Create an empty signature container object.
        CBORMap csfContainer = new CBORMap();

        // The map to sign may optionally be wrapped in a tag.
        CBORObject objectToSign = intercepter.wrap(mapToSign);

        // Get optional custom data.
        CBORObject customData = intercepter.getCustomData();
        if (customData != null) {
            csfContainer.set(CUSTOM_DATA_LABEL, customData);
        }

        // Add the mandatory signature algorithm.
        csfContainer.set(ALGORITHM_LABEL, new CBORInt(getAlgorithm().getCoseAlgorithmId()));
        
        // Add a keyId if there is one.
        if (optionalKeyId != null) {
            csfContainer.set(KEY_ID_LABEL, optionalKeyId);
        }
        
        // Asymmetric key signatures add specific items to the signature container.
        additionalItems(csfContainer);
        
        // Add the prepared signature object to the map object we want to sign. 
        mapToSign.set(key, csfContainer);

        // Finally, sign all but the signature label and associated value.
        csfContainer.set(SIGNATURE_LABEL, new CBORBytes(coreSigner(objectToSign.encode())));

        // Return the now signed object.
        return objectToSign;
    }
}
