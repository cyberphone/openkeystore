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
package org.webpki.json;

import java.math.BigDecimal;
import java.math.BigInteger;

import java.security.KeyPair;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.util.EnumSet;
import java.util.GregorianCalendar;
import java.util.ArrayList;

import java.util.regex.Pattern;

import org.webpki.crypto.AlgorithmPreferences;

import org.webpki.util.Base64URL;
import org.webpki.util.ISODateTime;

/**
 * JSON object reader.
 * <p>
 * Returned by the parser methods.
 * Also provides built-in support for decoding
 * <a href="https://cyberphone.github.io/doc/security/jsf.html" target="_blank">
 * <b>JSF (JSON Signature Format)</b></a>
 * and
 * <a href="https://cyberphone.github.io/doc/security/jef.html" target="_blank">
 * <b>JEF (JSON Encryption Format)</b></a>
 * constructs.</p>
 * <p>In addition,
 * there are methods for reading keys supplied in the
 * <a href="https://tools.ietf.org/html/rfc7517" target="_blank"><b>JWK (JSON Web Key)</b></a>
 * format.
 * @see JSONParser
 * @see #getObject(String)
 * @see JSONArrayReader#getObject()
 * @see JSONObjectWriter#JSONObjectWriter(JSONObjectReader)
 */
public class JSONObjectReader implements Cloneable {

    static final Pattern DECIMAL_PATTERN = Pattern.compile("-?([1-9][0-9]*|0)(\\.[0-9]+)?");
    static final Pattern INTEGER_PATTERN = Pattern.compile("-?[1-9][0-9]*|0");

    JSONObject root;

    JSONObjectReader(JSONObject root) {
        this.root = root;
    }

    /**
     * Create a JSON object reader from of a writer.
     * @param objectWriter The writer object
     */
    public JSONObjectReader(JSONObjectWriter objectWriter) {
        this(objectWriter.root);
    }

    /**
     * Check for unread data.
     * Throws an exception if any property or array element in the current object or
     * child objects have not been read.
     * @see JSONObjectReader#scanAway(String)
     * @see JSONObjectReader#getPropertyType(String)
     * @see JSONObjectReader#getProperties()
     */
    public void checkForUnread() {
        if (getJSONArrayReader() == null) {
            JSONObject.checkObjectForUnread(root);
        } else {
            JSONObject.checkArrayForUnread(root.properties.get(null), "Outer");
        }
    }

    JSONValue getProperty(String name) {
        JSONValue value = root.properties.get(name);
        if (value == null) {
            throw new JSONException("Property \"" + name + "\" is missing");
        }
        return value;
    }

    JSONValue getProperty(String name, JSONTypes expectedType) {
        JSONValue value = getProperty(name);
        JSONTypes.compatibilityTest(expectedType, value);
        value.readFlag = true;
        return value;
    }

    void clearReadFlags() {
        for (JSONValue value : root.properties.values()) {
            value.readFlag = false;
        }
    }

    String getString(String name, JSONTypes expectedType) {
        JSONValue value = getProperty(name, expectedType);
        return (String) value.value;
    }

    /**
     * Read a JSON string property.
     * @param name Property
     * @return Java <code>String</code>
     * @see JSONObjectWriter#setString(String, String)
     */
    public String getString(String name) {
        return getString(name, JSONTypes.STRING);
    }

    static long int53Check(long value) {
        if (value > JSONObjectWriter.MAX_INTEGER || value < -JSONObjectWriter.MAX_INTEGER) {
            throw new JSONException("Int53 values must not exceeed abs(" +
                    JSONObjectWriter.MAX_INTEGER +
                    "), found: " + value);
        }
        return value;
    }

    static long parseLong(JSONValue jsonValue) {
        return int53Check(Long.valueOf((String) jsonValue.value));
    }

    static int parseInt(JSONValue jsonValue) {
        long value = parseLong(jsonValue);
        if (value > Integer.MAX_VALUE || value < Integer.MIN_VALUE) {
            throw new JSONException("Int32 value out of range: " + value);
        }
        return (int) value;
    }

    static long convertBigIntegerToLong(BigInteger value) {
        long longValue = value.longValue();
        if (BigInteger.valueOf(longValue).compareTo(value) != 0) {
            throw new JSONException("Int64 value out of range: " + value);
        }
        return longValue;
    }

    /**
     * Read a JSON integer property.<p>
     * This method only accepts true integer values.  I.e. 10.4 would throw an exception.</p>
     * @param name Property
     * @return Java <code>int</code>
     * @see JSONObjectWriter#setInt(String, int)
     */
    public int getInt(String name) {
        return parseInt(getProperty(name, JSONTypes.NUMBER));
    }

    /**
     * Read a JSON long integer property.<p>
     * This method only accepts true integer values.  I.e. 10.4 would throw an exception.</p><p>
     * Note: Only 53 bits of precision is available,
     * values outside this range throw exceptions.</p>
     * @param name Property
     * @return Java <code>long</code>
     * @see JSONObjectWriter#setInt53(String, long)
     * @see JSONObjectWriter#MAX_INTEGER
     * @see #getBigInteger(String)
     */
    public long getInt53(String name) {
        return parseLong(getProperty(name, JSONTypes.NUMBER));
    }

    /**
     * Read a JSON long integer property.<p>
     * This method only accepts true integer values.  I.e. 10.4 would throw an exception.</p><p>
     * Note: The value is put within quotes to maintain full 64-bit precision
     * which does not have a native counterpart in JavaScript.</p>
     * @param name Property
     * @return Java <code>long</code>
     * @see JSONObjectWriter#setLong(String, long)
     * @see #getBigInteger(String)
     * @see #getInt53(String)
     */
    public long getLong(String name) {
        return convertBigIntegerToLong(getBigInteger(name));
    }

    /**
     * Read a JSON double property.
     * @param name Property
     * @return Java <code>double</code>
     * @see JSONObjectWriter#setDouble(String, double)
     */
    public double getDouble(String name) {
        return Double.valueOf(getString(name, JSONTypes.NUMBER));
    }

    /**
     * Read JSON boolean property.
     * @param name Property
     * @return Java <code>boolean</code>
     * @see JSONObjectWriter#setBoolean(String, boolean)
     */
    public boolean getBoolean(String name) {
        return Boolean.valueOf(getString(name, JSONTypes.BOOLEAN));
    }

    /**
     * Read a JSON dateTime property in ISO format.<p>
     * Note: Since JSON does not support a native dateTime 
     * type, this method builds on <i>mapping</i>.</p>
     * @param name Property
     * @param constraints Required input format
     * @return Java <code>GregorianCalendar</code>
     * @see org.webpki.util.ISODateTime#decode(String, EnumSet)
     * @see JSONObjectWriter#setDateTime(String, GregorianCalendar, EnumSet)
     */
    public GregorianCalendar getDateTime(String name, 
                                         EnumSet<ISODateTime.DatePatterns> constraints) 
    {
        return ISODateTime.decode(getString(name), constraints);
    }

    /**
     * Read a base64url encoded JSON property.
     * @param name Property
     * @return Java <code>byte[]</code>
     * @see JSONObjectWriter#setBinary(String, byte[])
     */
    public byte[] getBinary(String name) {
        return Base64URL.decode(getString(name));
    }

    /**
     * Conditionally read a base64url encoded JSON property.
     * @param name Property
     * @return Java <code>byte[]</code> or <b>null</b> if property is not present
     * @see JSONObjectWriter#setBinary(String, byte[])
     */
    public byte[] getBinaryConditional(String name) {
        return hasProperty(name) ? getBinary(name) : null;
    }

    static BigDecimal parseMoney(String value, Integer decimals) {
        if (INTEGER_PATTERN.matcher(value).matches() ||
                DECIMAL_PATTERN.matcher(value).matches()) {
            BigDecimal parsed = new BigDecimal(value);
            if (decimals != null && parsed.scale() != decimals) {
                throw new JSONException("Incorrect number of decimals in \"Money\": " + 
                                      parsed.scale());
            }
            return parsed;
        }
        throw new JSONException("Malformed \"Money\": " + value);
    }

    /**
     * Read a Money property.<p>
     * Note: Since JSON does not support a native Money type, 
     * this method builds on <i>mapping</i>.</p>
     * @param name Property
     * @return Java <code>BigInteger</code>
     * @see JSONObjectWriter#setMoney(String, BigDecimal)
     */
    public BigDecimal getMoney(String name) {
        return parseMoney(getString(name), null);
    }

    /**
     * Read a Money property.<p>
     * Note: Since JSON does not support a native Money type, 
     * this method builds on <i>mapping</i>.</p>
     * @param name Property
     * @param decimals Required number of fractional digits or <b>null</b> if unspecified
     * @return Java <code>BigDecimal</code>
     * @see JSONObjectWriter#setMoney(String, BigDecimal, int)
     */
    public BigDecimal getMoney(String name, int decimals) {
        return parseMoney(getString(name), decimals);
    }

    static BigDecimal parseBigDecimal(String value) {
        if (JSONParser.NUMBER_PATTERN.matcher(value).matches()) {
            return new BigDecimal(value);
        }
        throw new JSONException("Malformed \"getBigDecimal\": " + value);
    }

    /**
     * Read a BigDecimal property.<p>
     * Note: Since JSON does not support a native BigDecimal type, 
     * this method builds on <i>mapping</i>.</p>
     * @param name Property
     * @return Java <code>BigInteger</code>
     * @see JSONObjectWriter#setBigDecimal(String, BigDecimal)
     */
    public BigDecimal getBigDecimal(String name) {
        return parseBigDecimal(getString(name));
    }

    static BigInteger parseBigInteger(String value) {
        if (INTEGER_PATTERN.matcher(value).matches()) {
            return new BigInteger(value);
        }
        throw new JSONException("Malformed \"BigInteger\": " + value);
    }

    /**
     * Read a BigInteger property.<p>
     * Note: Since JSON does not support a native BigInteger type, 
     * this method builds on <i>mapping</i>.</p>
     * @param name Property
     * @return Java <code>BigInteger</code>
     * @see JSONObjectWriter#setBigInteger(String, BigInteger)
     */
    public BigInteger getBigInteger(String name) {
        return parseBigInteger(getString(name));
    }

    /**
     * Get root array reader.<p>
     * If the outermost part of the JSON structure is an array, this method <b>must</b> be
     * called <i>immediately after parsing</i> in order to process the structure.</p>
     * @return Array reader if array else <b>null</b>
     * @see JSONArrayWriter#JSONArrayWriter()
     */
    @SuppressWarnings("unchecked")
    public JSONArrayReader getJSONArrayReader() {
        return root.properties.containsKey(null) ?
                new JSONArrayReader((ArrayList<JSONValue>) root.properties.get(null).value) : null;
    }

    /**
     * Conditionally read a JSON <b>null</b> property.<p>
     * Note: Only if the property contains a <b>null</b> the property is marked as "read".</p>
     * @param name Property
     * @return <code>true</code> if <b>null</b> was found, else <code>false</code>
     * @see JSONObjectReader#checkForUnread()
     */
    public boolean getIfNULL(String name) {
        if (getPropertyType(name) == JSONTypes.NULL) {
            scanAway(name);
            return true;
        }
        return false;
    }

    /**
     * Read a JSON object property.
     * @param name Property
     * @return Object reader
     */
    public JSONObjectReader getObject(String name) {
        JSONValue value = getProperty(name, JSONTypes.OBJECT);
        return new JSONObjectReader((JSONObject) value.value);
    }

    /**
     * Read a JSON array property.
     * @param name Property
     * @return Array reader
     */
    @SuppressWarnings("unchecked")
    public JSONArrayReader getArray(String name) {
        JSONValue value = getProperty(name, JSONTypes.ARRAY);
        return new JSONArrayReader((ArrayList<JSONValue>) value.value);
    }

    /**
     * Conditionally read a JSON string property.<br>
     * Note: This method is equivalent to <code>getStringConditional(name, null)</code>.
     * @param name Property
     * @return The <code>String</code> if available else <b>null</b>
     */
    public String getStringConditional(String name) {
        return this.getStringConditional(name, null);
    }

    /**
     * Conditionally read a JSON string property.<br>
     * @param name Property
     * @param defaultValue Default value including possibly <b>null</b>
     * @return The <code>String</code> if available else <code>defaultValue</code>
     */
    public String getStringConditional(String name, String defaultValue) {
        return hasProperty(name) ? getString(name) : defaultValue;
    }

    /**
     * Conditionally read a JSON boolean property.<br>
     * @param name Property
     * @return The boolean if available else <code>false</code>
     */
    public boolean getBooleanConditional(String name) {
        return this.getBooleanConditional(name, false);
    }

    /**
     * Conditionally read a JSON boolean property.<br>
     * @param name Property
     * @param defaultValue Default value
     * @return The boolean if available else <code>defaultValue</code>
     */
    public boolean getBooleanConditional(String name, boolean defaultValue) {
        return hasProperty(name) ? getBoolean(name) : defaultValue;
    }

    /**
     * Conditionally read an array of JSON strings.
     * @param name Property
     * @return Array of <code>String</code> or <b>null</b> if property is not present
     */
    public String[] getStringArrayConditional(String name) {
        return hasProperty(name) ? getStringArray(name) : null;
    }

    String[] getSimpleArray(String name, JSONTypes expectedType) {
        ArrayList<String> array = new ArrayList<>();
        @SuppressWarnings("unchecked")
        ArrayList<JSONValue> arrayElements = 
            ((ArrayList<JSONValue>) getProperty(name, JSONTypes.ARRAY).value);
        for (JSONValue value : arrayElements) {
            JSONTypes.compatibilityTest(expectedType, value);
            value.readFlag = true;
            array.add((String) value.value);
        }
        return array.toArray(new String[0]);
    }

    /**
     * Read an array of JSON strings.
     * @param name Property
     * @return Array of <code>String</code>
     */
    public String[] getStringArray(String name) {
        return getSimpleArray(name, JSONTypes.STRING);
    }

    /**
     * Read an array of base64url encoded JSON strings.
     * @param name Property
     * @return ArrayList holding arrays of bytes
     */
    public ArrayList<byte[]> getBinaryArray(String name) {
        return getArray(name).getBinaryArray();
    }

    /**
     * Get JSON properties.<br>
     * @return All properties of the current object
     */
    public String[] getProperties() {
        return root.properties.keySet().toArray(new String[0]);
    }

    /**
     * Test if a property is present.
     * @param name Property
     * @return <code>true</code> if object is present, else <code>false</code>
     * @see JSONObjectReader#getPropertyType(String)
     */
    public boolean hasProperty(String name) {
        return root.properties.get(name) != null;
    }

    /**
     * Get the native JSON type of a property.
     * @param name Property
     * @return JSON type
     * @see org.webpki.json.JSONTypes
     * @see JSONObjectReader#hasProperty(String)
     */
    public JSONTypes getPropertyType(String name) {
        return getProperty(name).type;
    }

    /**
     * Read and decode a <a href="https://cyberphone.github.io/doc/security/jsf.html" target="_blank"><b>JSF</b></a>
     * signature object.
     * 
     * @param options Allowed/expected options
     * @return An object which can be used to verify keys etc.
     * @see org.webpki.json.JSONObjectWriter#setSignature(JSONSigner)
     * @see org.webpki.json.JSONCryptoHelper.Options
     */
    public JSONSignatureDecoder getSignature(JSONCryptoHelper.Options options) {
        return getSignature(JSONObjectWriter.SIGNATURE_DEFAULT_LABEL_JSON, options);
    }

    public JSONSignatureDecoder getSignature(String signatureLabel, 
                                             JSONCryptoHelper.Options options) {
        options.initializeOperation(false);
        JSONObjectReader signatureObject = getObject(signatureLabel);
        if (signatureObject.hasProperty(JSONCryptoHelper.SIGNERS_JSON)) {
            throw new JSONException("Use \"getMultiSignature()\" for this object");
        }
        if (signatureObject.hasProperty(JSONCryptoHelper.CHAIN_JSON)) {
            throw new JSONException("Use \"getSignatureChain()\" for this object");
        }
        return new JSONSignatureDecoder(this, signatureObject, signatureObject, options);
    }
    
    ArrayList<JSONSignatureDecoder> getSignatureArray(String signatureLabel, 
                                                      JSONCryptoHelper.Options options,
                                                      boolean chained) {
        options.initializeOperation(false);
        JSONObjectReader outerSignatureObject = getObject(signatureLabel);
        JSONArrayReader arrayReader = 
                outerSignatureObject.getArray(chained ?
                        JSONCryptoHelper.CHAIN_JSON : JSONCryptoHelper.SIGNERS_JSON);
        @SuppressWarnings("unchecked")
        ArrayList<JSONValue> save = (ArrayList<JSONValue>) arrayReader.array.clone();
        ArrayList<JSONSignatureDecoder> signatures = new ArrayList<>();
        ArrayList<JSONObjectReader> signatureObjects = new ArrayList<>();
        do {
            signatureObjects.add(arrayReader.getObject());
        } while(arrayReader.hasMore());
        arrayReader.array.clear();
        for (JSONObjectReader innerSignatureObject : signatureObjects) {
            if (!chained) {
                arrayReader.array.clear();
            }
            arrayReader.array.add(new JSONValue(JSONTypes.OBJECT,
                                                innerSignatureObject.root));
            signatures.add(new JSONSignatureDecoder(this, 
                                                    innerSignatureObject,
                                                    outerSignatureObject,
                                                    options));
        }
        arrayReader.array.clear();
        arrayReader.array.addAll(save);
        return signatures;
    }

    /**
     * Read and decode a
     * <a href="https://cyberphone.github.io/doc/security/jsf.html" target="_blank"><b>JSF</b></a>
     * multi-signature object.
     * @param options Allowed/expected options
     * @return List with signature objects
     */
    public ArrayList<JSONSignatureDecoder> getMultiSignature(JSONCryptoHelper.Options options) {
        return getMultiSignature(JSONObjectWriter.SIGNATURE_DEFAULT_LABEL_JSON, options);
    }
    
    public ArrayList<JSONSignatureDecoder> getMultiSignature(String signatureLabel, 
                                                             JSONCryptoHelper.Options options) {
        return getSignatureArray(signatureLabel, options, false);
    }

    /**
     * Read and decode a
     * <a href="https://cyberphone.github.io/doc/security/jsf.html" target="_blank"><b>JSF</b></a>
     * chained-signature object.
     * @param options Allowed/expected options
     * @return List with signature objects
     */
    public ArrayList<JSONSignatureDecoder> getSignatureChain(JSONCryptoHelper.Options options) {
        return getSignatureChain(JSONObjectWriter.SIGNATURE_DEFAULT_LABEL_JSON, options);
    }
    
    public ArrayList<JSONSignatureDecoder> getSignatureChain(String signatureLabel, 
                                                             JSONCryptoHelper.Options options) {
        return getSignatureArray(signatureLabel, options, true);
    }

    /**
     * Read and decode a public key in
     * <a href="https://cyberphone.github.io/doc/security/jsf.html" target="_blank"><b>JSF</b></a>
     * (<a href="https://tools.ietf.org/html/rfc7517" target="_blank"><b>JWK</b></a>) format.
     * 
     * @param algorithmPreferences JOSE or SKS notation expected
     * @return Java <code>PublicKey</code>
     * @see org.webpki.json.JSONObjectWriter#setPublicKey(PublicKey)
     */
    public PublicKey getPublicKey(AlgorithmPreferences algorithmPreferences) {
        return getObject(JSONCryptoHelper.PUBLIC_KEY_JSON).getCorePublicKey(algorithmPreferences);
    }

    /**
     * Read and decode a public key in
     * <a href="https://cyberphone.github.io/doc/security/jsf.html" target="_blank"><b>JSF</b></a>
     * (<a href="https://tools.ietf.org/html/rfc7517" target="_blank"><b>JWK</b></a>) format.
     * This method is equivalent to <code>getPublicKey(AlgorithmPreferences.JOSE)</code>.
     * 
     * @return Java <code>PublicKey</code>
     * @see org.webpki.json.JSONObjectWriter#setPublicKey(PublicKey)
     */
    public PublicKey getPublicKey() {
        return getPublicKey(AlgorithmPreferences.JOSE);
    }

    /**
     * Read and decode a public key in
     * <a href="https://cyberphone.github.io/doc/security/jsf.html" target="_blank"><b>JSF</b></a>
     * (<a href="https://tools.ietf.org/html/rfc7517" target="_blank"><b>JWK</b></a>) format.
     * Note: this method assumes that the current object only holds the actual 
     * public key structure (no property).
     * 
     * @param algorithmPreferences JOSE or SKS notation expected
     * @return Java <code>PublicKey</code>
     * @see org.webpki.json.JSONObjectWriter#createCorePublicKey(PublicKey,AlgorithmPreferences)
     */
    public PublicKey getCorePublicKey(AlgorithmPreferences algorithmPreferences) {
        clearReadFlags();
        PublicKey publicKey = JSONCryptoHelper.decodePublicKey(this, algorithmPreferences);
        checkForUnread();
        return publicKey;
    }

    /**
     * Read a public and private key in 
     * <a href="https://tools.ietf.org/html/rfc7517" target="_blank"><b>JWK</b></a> format.<p>
     * Note: this method assumes that the current object only holds a JWK key structure.</p>
     * 
     * @param algorithmPreferences JOSE or SKS notation expected
     * @return Java <code>KeyPair</code>
     */
    public KeyPair getKeyPair(AlgorithmPreferences algorithmPreferences) {
        clearReadFlags();
        PublicKey publicKey = JSONCryptoHelper.decodePublicKey(this, algorithmPreferences);
        KeyPair keyPair =
                new KeyPair(publicKey, JSONCryptoHelper.decodePrivateKey(this, publicKey));
        checkForUnread();
        return keyPair;
    }

    /**
     * Read a public and private key in 
     * <a href="https://tools.ietf.org/html/rfc7517" target="_blank"><b>JWK</b></a> format.<p>
     * Note: this method assumes that the current object only holds a JWK key structure.</p>
     * This method is equivalent to <code>getKeyPair(AlgorithmPreferences.JOSE)</code>.
     * 
     * @return Java <code>KeyPair</code>
     */
    public KeyPair getKeyPair(){
        return getKeyPair(AlgorithmPreferences.JOSE);
    }

    /**
     * Read an object in
     * <a href="https://cyberphone.github.io/doc/security/jef.html" target="_blank"><b>JEF</b></a>
     * format.<p>
     * Note: this method assumes that the current object only holds a JEF structure.</p>
     * @param options Restrictions and requirements
     * @return An object which can be used to retrieve the original (unencrypted) data 
     * @see org.webpki.json.JSONObjectWriter#createEncryptionObject(byte[],ContentEncryptionAlgorithms,JSONEncrypter)
     * @see org.webpki.json.JSONCryptoHelper.Options
     */
    public JSONDecryptionDecoder getEncryptionObject(JSONCryptoHelper.Options options) {
        options.initializeOperation(true);
        if (hasProperty(JSONCryptoHelper.RECIPIENTS_JSON)) {
            throw new JSONException(
                    "Please use \"getEncryptionObjects()\" for multiple encryption objects");
        }
        boolean keyEncryption = hasProperty(JSONCryptoHelper.KEY_ENCRYPTION_JSON);
        JSONDecryptionDecoder.Holder holder = 
                new JSONDecryptionDecoder.Holder(options, this, keyEncryption);
        return new JSONDecryptionDecoder(
                holder, 
                keyEncryption ? getObject(JSONCryptoHelper.KEY_ENCRYPTION_JSON) : this,
                true);
    }

    /**
     * Read an object in
     * <a href="https://cyberphone.github.io/doc/security/jef.html" target="_blank"><b>JEF</b></a>
     * format intended for <i>multiple recipients</i>.<p>
     * Note: this method assumes that the current object only holds a JEF structure.</p>
     * @param options Global restrictions and requirements
     * @return An object which can be used to retrieve the original (unencrypted) data 
     * @see org.webpki.json.JSONObjectWriter#createEncryptionObject(byte[],ContentEncryptionAlgorithms,JSONEncrypter)
     * @see org.webpki.json.JSONCryptoHelper.Options
     */
    public ArrayList<JSONDecryptionDecoder> getEncryptionObjects(JSONCryptoHelper.Options options) {
        options.initializeOperation(true);
        JSONDecryptionDecoder.Holder holder = new JSONDecryptionDecoder.Holder(options, this, true);
        JSONArrayReader recipientObjects = getArray(JSONCryptoHelper.RECIPIENTS_JSON);
        ArrayList<JSONDecryptionDecoder> recipients = new ArrayList<>();
        do {
            JSONDecryptionDecoder decoder = new JSONDecryptionDecoder(holder, 
                                                                      recipientObjects.getObject(),
                                                                      !recipientObjects.hasMore());
            JSONDecryptionDecoder.keyWrapCheck(decoder.getKeyEncryptionAlgorithm());
            recipients.add(decoder);
        } while (recipientObjects.hasMore());
        return recipients;
    }

    /**
     * Read a certificate path in 
     * <a href="https://cyberphone.github.io/doc/security/jsf.html" target="_blank"><b>JSF</b></a>
     * format.
     * <p>The array elements (base64url encoded certificates),
     * <b>must</b> be supplied in <i>strict issuance order</i>
     * where certificate[i] is signed by certificate[i + 1].</p>
     * @return Certificate path
     * @see org.webpki.json.JSONObjectWriter#setCertificatePath(X509Certificate[])
     */
    public X509Certificate[] getCertificatePath() {
        return getArray(JSONCryptoHelper.CERTIFICATE_PATH_JSON).getCertificatePath();
    }

    /**
     * Scan a property.
     * This method scans a property regardless of its type and it useful for dealing with
     * data where the type is unknown.
     * It also marks the property as "read" including possible child objects and arrays. 
     * @param name Property
     * @return Current instance of {@link org.webpki.json.JSONObjectReader}
     * @see JSONObjectReader#checkForUnread()
     * @see JSONObjectReader#getPropertyType(String)
     * @see JSONObjectReader#getProperties()
     */
    public JSONObjectReader scanAway(String name) {
        JSONValue value = getProperty(name);
        value.readFlag = true;
        if (value.type == JSONTypes.OBJECT) {
            JSONObject.setObjectAsRead((JSONObject) value.value);
        } else if (value.type == JSONTypes.ARRAY) {
            JSONObject.setArrayAsRead(value);
        }
        return this;
    }

    /**
     * Remove a property.
     * @param name Property
     * @return Current instance of {@link org.webpki.json.JSONObjectReader}
     */
    public JSONObjectReader removeProperty(String name) {
        getProperty(name);
        root.properties.remove(name);
        return this;
    }

    /**
     * Serialize object reader to a Java <code>byte[]</code>.
     * @param outputFormat Any JSONOutputFormats
     * @return JSON string data
      */
    public byte[] serializeToBytes(JSONOutputFormats outputFormat) {
        return new JSONObjectWriter(root).serializeToBytes(outputFormat);
    }

    /**
     * Serialize object reader to a Java <code>String</code>.
     * @param outputFormat Any JSONOutputFormats
     * @return JSON string data
     */
     public String serializeToString(JSONOutputFormats outputFormat) {
        return new JSONObjectWriter(root).serializeToString(outputFormat);
    }

    /**
     * Deep copy of JSON object reader.
     */
    @Override
    public JSONObjectReader clone() {
        return JSONParser.parse(serializeToBytes(JSONOutputFormats.NORMALIZED));
    }

    /**
     * Pretty print JSON of object reader.
     */
    @Override
    public String toString() {
        return new JSONObjectWriter(root).toString();
    }
}
