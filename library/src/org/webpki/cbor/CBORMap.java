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

import java.util.Comparator;
import java.util.Map;
import java.util.TreeMap;

import org.webpki.util.ArrayUtil;

/**
 * Class for holding CBOR maps.
 * 
 * This class also provides support for signature creation and validation.
 */
public class CBORMap extends CBORObject {

    boolean parsingMode;
    CBORObject lastKey;

    private static Comparator<CBORObject> comparator = new Comparator<CBORObject>() {

        @Override
        public int compare(CBORObject o1, CBORObject o2) {
            try {
                byte[] key1 = o1.internalEncode();
                byte[] key2 = o2.internalEncode();
                if (rfc7049Sorting && key1.length != key2.length) {
                    return key1.length - key2.length;
                }
                int minIndex = Math.min(key1.length, key2.length);
                for (int i = 0; i < minIndex; i++) {
                    int diff = (key1[i] & 0xff) - (key2[i] & 0xff);
                    if (diff != 0) {
                        return diff;
                    }
                }
                return key1.length - key2.length;
            } catch (IOException e) {
                 throw new RuntimeException(e);
            }
        }
        
    };

    Map<CBORObject, CBORObject> keys = new TreeMap<>(comparator);

    public CBORMap() {
    }
    

    @Override
    CBORTypes internalGetType() {
        return CBORTypes.MAP;
    }
    
    /**
     * Get the size of the map.
     * 
     * @return The number of entries (keys) in the map
     */
    public int size() {
        return keys.size();
    }

    /**
     * Check map for key presence.
     * 
     * @param key Key
     * @return <code>true</code> if the key is present
     */
    public boolean hasKey(CBORObject key) {
        return keys.containsKey(key);
    }

    /**
     * Check map for key presence.
     * 
     * @param key Key
     * @return <code>true</code> if the key is present
     */
    public boolean hasKey(int key) {
        return hasKey(new CBORInteger(key));
    }
    
    /**
     * Check map for key presence.
     * 
     * @param key Key
     * @return <code>true</code> if the key is present
     */
    public boolean hasKey(String key) {
        return hasKey(new CBORTextString(key));
    }
    
    /**
     * Set map value.

     * @param key Key
     * @param value Value
     * @return <code>this</code>
     * @throws IOException
     */
    public CBORMap setObject(CBORObject key, CBORObject value) throws IOException {
        if (keys.put(key, value) != null) {
            bad("Duplicate key: " + key.toString());
        }
        if (parsingMode) {
            if (comparator.compare(lastKey, key) > 0) {
                bad("Improperly canonicalized key: " + key);
            }
        }
        lastKey = key;
        return this;
    }

    /**
     * Set map value.

     * @param key Key
     * @param value Value
     * @return <code>this</code>
     * @throws IOException
     */
    public CBORMap setObject(int key, CBORObject value) throws IOException {
        setObject(new CBORInteger(key), value);
        return this;
    }

    /**
     * Set map value.

     * @param key Key
     * @param value Value
     * @return <code>this</code>
     * @throws IOException
     */
    public CBORMap setObject(String key, CBORObject value) throws IOException {
        setObject(new CBORTextString(key), value);
        return this;
    }
    
     /**
     * Get map value.
     * 
     * @param key Key
     * @return Value
     * @throws IOException
     */
    public CBORObject getObject(CBORObject key) throws IOException {
        CBORObject cborObject = keys.get(key);
        if (cborObject == null) {
            bad("No such key: " + key.toString());
        }
        return cborObject;
    }

    /**
     * Get map value.
     * 
     * @param key Key
     * @return Value
     * @throws IOException
     */
    public CBORObject getObject(int key) throws IOException {
        return getObject(new CBORInteger(key));
    }
    
    /**
     * Get map value.
     * 
     * @param key Key
     * @return Value
     * @throws IOException
     */
    public CBORObject getObject(String key) throws IOException {
        return getObject(new CBORTextString(key));
    }
    
    /**
     * Remove object from map.
     * 
     * @param key Key
     * @return <code>this</code>
     * @throws IOException
     */
    public CBORMap removeObject(CBORObject key) throws IOException {
        if (!keys.containsKey(key)) {
            bad("No such key: " + key.toString());
        }
        keys.remove(key);
        return this;
    }

    /**
     * Remove object from map.
     * 
     * @param key Key
     * @return <code>this</code>
     * @throws IOException
     */
    public CBORMap removeObject(int key) throws IOException {
        removeObject(new CBORInteger(key));
        return this;
    }

    /**
     * Remove object from map.
     * 
     * @param key Key
     * @return <code>this</code>
     * @throws IOException
     */
    public CBORMap removeObject(String key) throws IOException {
        removeObject(new CBORTextString(key));
        return this;
    }

    /**
     * Validate signed CBOR map.
     * 
     * @param key Key in map holding signature
     * @param validator Validator
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public void validate(CBORObject key, CBORValidator validator) throws IOException, 
                                                                         GeneralSecurityException {
        // Fetch signature object
        CBORMap signatureObject = getObject(key).getMap();

        // Get the signature value.
        byte[] signatureValue = signatureObject
                .getObject(CBORSigner.SIGNATURE_LABEL).getByteString();

        // Remove the signature value label and its argument.
        // The remaining object is used for signature calculation.
        signatureObject.keys.remove(CBORSigner.SIGNATURE_LABEL);

        // Fetch optional keyId.
        byte[] optionalKeyId = signatureObject.hasKey(CBORSigner.KEY_ID_LABEL)
                ? signatureObject.getObject(CBORSigner.KEY_ID_LABEL)
                        .getByteString()
                : null;

        // Call specific validator.
        validator.validate(signatureObject,
                signatureObject.getObject(CBORSigner.ALGORITHM_LABEL).getInt(),
                optionalKeyId, signatureValue, internalEncode());

        // Check that nothing "extra" was supplied.
        signatureObject.checkForUnread();

        // Restore object.
        signatureObject.keys.put(CBORSigner.SIGNATURE_LABEL,
                new CBORByteString(signatureValue));
    }

    /**
     * Validate signed CBOR map.
     * 
     * @param key Key in map holding signature
     * @param validator Validator
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public void validate(int key, CBORValidator validator) throws IOException, 
                                                                  GeneralSecurityException {
        validate(new CBORInteger(key), validator);
    }
    
    /**
     * Validate signed CBOR map.
     * 
     * @param key Key in map holding signature
     * @param validator Validator
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public void validate(String key, CBORValidator validator) throws IOException, 
                                                                     GeneralSecurityException {
        validate(new CBORTextString(key), validator);
    }

    /**
     * Sign CBOR object.
     * 
     * @param key Key holding the signature in the map to sign
     * @param signer Holder of signature method and key
     * @return <code>this</code>
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public CBORMap sign(CBORObject key, CBORSigner signer) throws IOException, GeneralSecurityException {
        signer.sign(key, this);
        return this;
    }

    /**
     * Sign CBOR object.
     * 
     * @param key Key holding the signature in the map to sign
     * @param signer Holder of signature method and key
     * @return <code>this</code>
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public CBORMap sign(int key, CBORSigner signer) throws IOException, 
                                                                  GeneralSecurityException {
        return sign(new CBORInteger(key), signer);
    }

    /**
     * Sign CBOR object.
     * 
     * @param key Key holding the signature in the map to sign
     * @param signer Holder of signature method and key
     * @return <code>this</code>
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public CBORMap sign(String key, CBORSigner signer) 
            throws IOException, GeneralSecurityException {
        return sign(new CBORTextString(key), signer);
    }

    /**
     * Enumerate all keys in a map.
     * 
     * @return Array of keys
     * @throws IOException 
     */
    public CBORObject[] getKeys() throws IOException {
        return keys.keySet().toArray(new CBORObject[0]);
    }

    @Override
    byte[] internalEncode() throws IOException {
        byte[] encoded = getEncodedCore(MT_MAP, keys.size());
        for (CBORObject key : keys.keySet()) {
            encoded = ArrayUtil.add(encoded,
                                    ArrayUtil.add(key.internalEncode(), 
                                                  keys.get(key).internalEncode()));
        }
        return encoded;
    }
        
    @Override
    void internalToString(CBORObject.PrettyPrinter prettyPrinter) {
        prettyPrinter.beginStructure("{\n");
        boolean notFirst = false;
        for (CBORObject key : keys.keySet()) {
            CBORObject member = keys.get(key);
            if (notFirst) {
                prettyPrinter.insertComma();
            }
            notFirst = true;
            prettyPrinter.indent();
            key.internalToString(prettyPrinter);
            prettyPrinter.appendText(": ");
            member.internalToString(prettyPrinter);
            prettyPrinter.appendText("\n");
        }
        prettyPrinter.endStructure("}");
    }
}
