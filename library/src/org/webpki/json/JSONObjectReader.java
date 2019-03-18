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
package org.webpki.json;

import java.io.IOException;
import java.io.Serializable;

import java.math.BigDecimal;
import java.math.BigInteger;

import java.security.KeyPair;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.util.EnumSet;
import java.util.GregorianCalendar;
import java.util.Vector;

import java.util.regex.Pattern;

import org.webpki.crypto.AlgorithmPreferences;

import org.webpki.util.Base64URL;
import org.webpki.util.ISODateTime;

/**
 * JSON object reader.
 * <p>
 * Returned by the parser methods.
 * Also provides built-in support for decoding
 <a href="https://cyberphone.github.io/doc/security/jcs.html" target="_blank"><b>JCS (JSON Cleartext Signature)</b></a>
 and
<a href="https://cyberphone.github.io/doc/security/jef.html" target="_blank"><b>JEF (JSON Encryption Format)</b></a>
 constructs.</p>
 <p>In addition,
 there are methods for reading
 keys supplied in the <a href="https://tools.ietf.org/html/rfc7517" target="_blank"><b>JWK (JSON Web Key)</b></a>
 format.
 @see JSONParser
 @see #getObject(String)
 @see JSONArrayReader#getObject()
 @see JSONObjectWriter#JSONObjectWriter(JSONObjectReader)
 */
public class JSONObjectReader implements Serializable, Cloneable {

    private static final long serialVersionUID = 1L;

    static final Pattern DECIMAL_PATTERN = Pattern.compile("-?([1-9][0-9]*|0)[\\.][0-9]+");
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
     * @throws IOException &nbsp;
     * @see JSONObjectReader#scanAway(String)
     * @see JSONObjectReader#getPropertyType(String)
     * @see JSONObjectReader#getProperties()
     */
    public void checkForUnread() throws IOException {
        if (getJSONArrayReader() == null) {
            JSONObject.checkObjectForUnread(root);
        } else {
            JSONObject.checkArrayForUnread(root.properties.get(null), "Outer");
        }
    }

    JSONValue getProperty(String name) throws IOException {
        JSONValue value = root.properties.get(name);
        if (value == null) {
            throw new IOException("Property \"" + name + "\" is missing");
        }
        return value;
    }

    JSONValue getProperty(String name, JSONTypes expectedType) throws IOException {
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

    String getString(String name, JSONTypes expectedType) throws IOException {
        JSONValue value = getProperty(name, expectedType);
        return (String) value.value;
    }

    /**
     * Read a JSON string property.
     * @param name Property
     * @return Java <code>String</code>
     * @throws IOException &nbsp;
     * @see JSONObjectWriter#setString(String, String)
     */
    public String getString(String name) throws IOException {
        return getString(name, JSONTypes.STRING);
    }

    static long int53Check(long value) throws IOException {
        if (value > JSONObjectWriter.MAX_INTEGER || value < -JSONObjectWriter.MAX_INTEGER) {
            throw new IOException("Int53 values must not exceeed abs(" +
                    JSONObjectWriter.MAX_INTEGER +
                    "), found: " + value);
        }
        return value;
    }

    static long parseLong(JSONValue jsonValue) throws IOException {
        return int53Check(Long.valueOf((String) jsonValue.value));
    }

    static int parseInt(JSONValue jsonValue) throws IOException {
        long value = parseLong(jsonValue);
        if (value > Integer.MAX_VALUE || value < Integer.MIN_VALUE) {
            throw new IOException("Int32 value out of range: " + value);
        }
        return (int) value;
    }

    static long convertBigIntegerToLong(BigInteger value) throws IOException {
        long longValue = value.longValue();
        if (BigInteger.valueOf(longValue).compareTo(value) != 0) {
            throw new IOException("Int64 value out of range: " + value);
        }
        return longValue;
    }

    /**
     * Read a JSON integer property.<p>
     * This method only accepts true integer values.  I.e. 10.4 would throw an exception.</p>
     * @param name Property
     * @return Java <code>int</code>
     * @throws IOException &nbsp;
     * @see JSONObjectWriter#setInt(String, int)
     */
    public int getInt(String name) throws IOException {
        return parseInt(getProperty(name, JSONTypes.NUMBER));
    }

    /**
     * Read a JSON long integer property.<p>
     * This method only accepts true integer values.  I.e. 10.4 would throw an exception.</p><p>
     * Note: Only 53 bits of precision is available,
     * values outside this range throw exceptions.</p>
     * @param name Property
     * @return Java <code>long</code>
     * @throws IOException &nbsp;
     * @see JSONObjectWriter#setInt53(String, long)
     * @see JSONObjectWriter#MAX_INTEGER
     * @see #getBigInteger(String)
     */
    public long getInt53(String name) throws IOException {
        return parseLong(getProperty(name, JSONTypes.NUMBER));
    }

    /**
     * Read a JSON long integer property.<p>
     * This method only accepts true integer values.  I.e. 10.4 would throw an exception.</p><p>
     * Note: The value is put within quotes to maintain full 64-bit precision
     * which does not have a native counterpart in JavaScript.</p>
     * @param name Property
     * @return Java <code>long</code>
     * @throws IOException &nbsp;
     * @see JSONObjectWriter#setLong(String, long)
     * @see #getBigInteger(String)
     * @see #getInt53(String)
     */
    public long getLong(String name) throws IOException {
        return convertBigIntegerToLong(getBigInteger(name));
    }

    /**
     * Read a JSON double property.
     * @param name Property
     * @return Java <code>double</code>
     * @throws IOException &nbsp;
     * @see JSONObjectWriter#setDouble(String, double)
     */
    public double getDouble(String name) throws IOException {
        return Double.valueOf(getString(name, JSONTypes.NUMBER));
    }

    /**
     * Read JSON boolean property.
     * @param name Property
     * @return Java <code>boolean</code>
     * @throws IOException &nbsp;
     * @see JSONObjectWriter#setBoolean(String, boolean)
     */
    public boolean getBoolean(String name) throws IOException {
        return new Boolean(getString(name, JSONTypes.BOOLEAN));
    }

    /**
     * Read a JSON dateTime property in ISO format.<p>
     * Note: Since JSON does not support a native dateTime type, this method builds on <i>mapping</i>.</p>
     * @param name Property
     * @param format Required input format
     * @return Java <code>GregorianCalendar</code>
     * @throws IOException &nbsp;
     * @see org.webpki.util.ISODateTime#parseDateTime(String, EnumSet)
     * @see JSONObjectWriter#setDateTime(String, GregorianCalendar, EnumSet)
     */
    public GregorianCalendar getDateTime(String name, 
                                         EnumSet<ISODateTime.DatePatterns> format) throws IOException {
        return ISODateTime.parseDateTime(getString(name), format);
    }

    /**
     * Read a base64url encoded JSON property.
     * @param name Property
     * @return Java <code>byte[]</code>
     * @throws IOException &nbsp;
     * @see JSONObjectWriter#setBinary(String, byte[])
     */
    public byte[] getBinary(String name) throws IOException {
        return Base64URL.decode(getString(name));
    }

    /**
     * Conditionally read a base64url encoded JSON property.
     * @param name Property
     * @return Java <code>byte[]</code> or <b>null</b> if property is not present
     * @throws IOException &nbsp;
     * @see JSONObjectWriter#setBinary(String, byte[])
     */
    public byte[] getBinaryConditional(String name) throws IOException {
        return hasProperty(name) ? getBinary(name) : null;
    }

    static BigDecimal parseMoney(String value, Integer decimals) throws IOException {
        if (INTEGER_PATTERN.matcher(value).matches() ||
                DECIMAL_PATTERN.matcher(value).matches()) {
            BigDecimal parsed = new BigDecimal(value);
            if (decimals != null && parsed.scale() != decimals) {
                throw new IOException("Incorrect number of decimals in \"BigDecimal\": " + parsed.scale());
            }
            return parsed;
        }
        throw new IOException("Malformed \"BigDecimal\": " + value);
    }

    /**
     * Read a Money property.<p>
     * Note: Since JSON does not support a native Money type, this method builds on <i>mapping</i>.</p>
     * Note: This method is equivalent to <code>getMoney(name, null)</code>.
     * @param name Property
     * @return Java <code>BigInteger</code>
     * @throws IOException &nbsp;
     * @see JSONObjectWriter#setMoney(String, BigDecimal)
     */
    public BigDecimal getMoney(String name) throws IOException {
        return parseMoney(getString(name), null);
    }

    /**
     * Read a Money property.<p>
     * Note: Since JSON does not support a native Money type, this method builds on <i>mapping</i>.</p>
     * @param name Property
     * @param decimals Required number of fractional digits or <b>null</b> if unspecified
     * @return Java <code>BigDecimal</code>
     * @throws IOException &nbsp;
     * @see JSONObjectWriter#setMoney(String, BigDecimal, Integer)
     */
    public BigDecimal getMoney(String name, Integer decimals) throws IOException {
        return parseMoney(getString(name), decimals);
    }

    static BigDecimal parseBigDecimal(String value) throws IOException {
        if (JSONParser.NUMBER_PATTERN.matcher(value).matches()) {
            return new BigDecimal(value);
        }
        throw new IOException("Malformed \"getBigDecimal\": " + value);
    }

    /**
     * Read a BigDecimal property.<p>
     * Note: Since JSON does not support a native BigDecimal type, this method builds on <i>mapping</i>.</p>
     * @param name Property
     * @return Java <code>BigInteger</code>
     * @throws IOException &nbsp;
     * @see JSONObjectWriter#setBigDecimal(String, BigDecimal)
     */
    public BigDecimal getBigDecimal(String name) throws IOException {
        return parseBigDecimal(getString(name));
    }

    static BigInteger parseBigInteger(String value) throws IOException {
        if (INTEGER_PATTERN.matcher(value).matches()) {
            return new BigInteger(value);
        }
        throw new IOException("Malformed \"BigInteger\": " + value);
    }

    /**
     * Read a BigInteger property.<p>
     * Note: Since JSON does not support a native BigInteger type, this method builds on <i>mapping</i>.</p>
     * @param name Property
     * @return Java <code>BigInteger</code>
     * @throws IOException &nbsp;
     * @see JSONObjectWriter#setBigInteger(String, BigInteger)
     */
    public BigInteger getBigInteger(String name) throws IOException {
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
        return root.properties.containsKey(null) ? new JSONArrayReader((Vector<JSONValue>) root.properties.get(null).value) : null;
    }

    /**
     * Conditionally read a JSON <b>null</b> property.<p>
     * Note: Only if the property contains a <b>null</b> the property is marked as "read".</p>
     * @param name Property
     * @return <code>true</code> if <b>null</b> was found, else <code>false</code>
     * @throws IOException &nbsp;
     * @see JSONObjectReader#checkForUnread()
     */
    public boolean getIfNULL(String name) throws IOException {
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
     * @throws IOException &nbsp;
     */
    public JSONObjectReader getObject(String name) throws IOException {
        JSONValue value = getProperty(name, JSONTypes.OBJECT);
        return new JSONObjectReader((JSONObject) value.value);
    }

    /**
     * Read a JSON array property.
     * @param name Property
     * @return Array reader
     * @throws IOException &nbsp;
     */
    @SuppressWarnings("unchecked")
    public JSONArrayReader getArray(String name) throws IOException {
        JSONValue value = getProperty(name, JSONTypes.ARRAY);
        return new JSONArrayReader((Vector<JSONValue>) value.value);
    }

    /**
     * Conditionally read a JSON string property.<br>
     * Note: This method is equivalent to <code>getStringConditional(name, null)</code>.
     * @param name Property
     * @return The <code>String</code> if available else <b>null</b>
     * @throws IOException &nbsp;
     */
    public String getStringConditional(String name) throws IOException {
        return this.getStringConditional(name, null);
    }

    /**
     * Conditionally read a JSON string property.<br>
     * @param name Property
     * @param defaultValue Default value including possibly <b>null</b>
     * @return The <code>String</code> if available else <code>defaultValue</code>
     * @throws IOException &nbsp;
     */
    public String getStringConditional(String name, String defaultValue) throws IOException {
        return hasProperty(name) ? getString(name) : defaultValue;
    }

    /**
     * Conditionally read a JSON boolean property.<br>
     * @param name Property
     * @return The boolean if available else <code>false</code>
     * @throws IOException &nbsp;
     */
    public boolean getBooleanConditional(String name) throws IOException {
        return this.getBooleanConditional(name, false);
    }

    /**
     * Conditionally read a JSON boolean property.<br>
     * @param name Property
     * @param defaultValue Default value
     * @return The boolean if available else <code>defaultValue</code>
     * @throws IOException &nbsp;
     */
    public boolean getBooleanConditional(String name, boolean defaultValue) throws IOException {
        return hasProperty(name) ? getBoolean(name) : defaultValue;
    }

    /**
     * Conditionally read an array of JSON strings.
     * @param name Property
     * @return Array of <code>String</code> or <b>null</b> if property is not present
     * @throws IOException &nbsp;
     */
    public String[] getStringArrayConditional(String name) throws IOException {
        return hasProperty(name) ? getStringArray(name) : null;
    }

    String[] getSimpleArray(String name, JSONTypes expectedType) throws IOException {
        Vector<String> array = new Vector<String>();
        @SuppressWarnings("unchecked")
        Vector<JSONValue> arrayElements = ((Vector<JSONValue>) getProperty(name, JSONTypes.ARRAY).value);
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
     * @throws IOException &nbsp;
     */
    public String[] getStringArray(String name) throws IOException {
        return getSimpleArray(name, JSONTypes.STRING);
    }

    /**
     * Read an array of base64url encoded JSON strings.
     * @param name Property
     * @return Vector holding arrays of bytes
     * @throws IOException &nbsp;
     */
    public Vector<byte[]> getBinaryArray(String name) throws IOException {
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
     * @throws IOException &nbsp;
     * @see org.webpki.json.JSONTypes
     * @see JSONObjectReader#hasProperty(String)
     */
    public JSONTypes getPropertyType(String name) throws IOException {
        return getProperty(name).type;
    }

    /**
     * Read and decode a <a href="https://cyberphone.github.io/doc/security/jcs.html" target="_blank"><b>JCS</b></a>
     * <code>"signature"</code> object.
     * 
     * @param options Allowed/expected options
     * @return An object which can be used to verify keys etc.
     * @throws IOException &nbsp;
     * @see org.webpki.json.JSONObjectWriter#setSignature(JSONSigner)
     * @see org.webpki.json.JSONCryptoHelper.Options
     */
    public JSONSignatureDecoder getSignature(JSONCryptoHelper.Options options) throws IOException {
        return getSignature(JSONObjectWriter.SIGNATURE_DEFAULT_LABEL_JSON, options);
    }

    public JSONSignatureDecoder getSignature(String signatureLabel, JSONCryptoHelper.Options options) throws IOException {
        options.encryptionMode(false);
        JSONObjectReader signatureObject = getObject(signatureLabel);
        if (signatureObject.hasProperty(JSONCryptoHelper.SIGNERS_JSON)) {
            throw new IOException("Use \"getMultiSignature()\" for this object");
        }
        return new JSONSignatureDecoder(this, signatureObject, signatureObject, options);
    }

    /**
     * Read and decode a
     * <a href="https://cyberphone.github.io/doc/security/jcs.html" target="_blank"><b>JCS</b></a>
     * <code>"signatures"</code> [] object.
     * @param options Allowed/expected options
     * @return List with signature objects
     * @throws IOException &nbsp;
     */
    public Vector<JSONSignatureDecoder> getMultiSignature(JSONCryptoHelper.Options options) throws IOException {
        return getMultiSignature(JSONObjectWriter.SIGNATURE_DEFAULT_LABEL_JSON, options);
    }
    
    public Vector<JSONSignatureDecoder> getMultiSignature(String signatureLabel, JSONCryptoHelper.Options options) throws IOException {
        options.encryptionMode(false);
        JSONObjectReader outerSignatureObject = getObject(signatureLabel);
        JSONArrayReader arrayReader = outerSignatureObject.getArray(JSONCryptoHelper.SIGNERS_JSON);
        @SuppressWarnings("unchecked")
        Vector<JSONValue> save = (Vector<JSONValue>) arrayReader.array.clone();
        Vector<JSONSignatureDecoder> signatures = new Vector<JSONSignatureDecoder>();
        Vector<JSONObjectReader> signatureObjects = new Vector<JSONObjectReader>();
        do {
            signatureObjects.add(arrayReader.getObject());
        } while(arrayReader.hasMore());
        for (JSONObjectReader innerSignatureObject : signatureObjects) {
            arrayReader.array.clear();
            arrayReader.array.add(new JSONValue(JSONTypes.OBJECT, innerSignatureObject.root));
            signatures.add(new JSONSignatureDecoder(this, innerSignatureObject, outerSignatureObject, options));
        }
        arrayReader.array.clear();
        arrayReader.array.addAll(save);
        return signatures;
    }

    /**
     * Read and decode a public key in
     * <a href="https://cyberphone.github.io/doc/security/jcs.html" target="_blank"><b>JCS</b></a>
     * (<a href="https://tools.ietf.org/html/rfc7517" target="_blank"><b>JWK</b></a>) format.
     * 
     * @param algorithmPreferences JOSE or SKS notation expected
     * @return Java <code>PublicKey</code>
     * @throws IOException &nbsp;
     * @see org.webpki.json.JSONObjectWriter#setPublicKey(PublicKey)
     */
    public PublicKey getPublicKey(AlgorithmPreferences algorithmPreferences) throws IOException {
        return getObject(JSONCryptoHelper.PUBLIC_KEY_JSON).getCorePublicKey(algorithmPreferences);
    }

    /**
     * Read and decode a public key in
     * <a href="https://cyberphone.github.io/doc/security/jcs.html" target="_blank"><b>JCS</b></a>
     * (<a href="https://tools.ietf.org/html/rfc7517" target="_blank"><b>JWK</b></a>) format.
     * This method is equivalent to <code>getPublicKey(AlgorithmPreferences.JOSE)</code>.
     * 
     * @return Java <code>PublicKey</code>
     * @throws IOException &nbsp;
     * @see org.webpki.json.JSONObjectWriter#setPublicKey(PublicKey)
     */
    public PublicKey getPublicKey() throws IOException {
        return getPublicKey(AlgorithmPreferences.JOSE);
    }

    /**
     * Read and decode a public key in
     * <a href="https://cyberphone.github.io/doc/security/jcs.html" target="_blank"><b>JCS</b></a>
     * (<a href="https://tools.ietf.org/html/rfc7517" target="_blank"><b>JWK</b></a>) format.
     * Note: this method assumes that the current object only holds the actual public key structure (no property).
     * 
     * @param algorithmPreferences JOSE or SKS notation expected
     * @return Java <code>PublicKey</code>
     * @throws IOException &nbsp;
     * @see org.webpki.json.JSONObjectWriter#createCorePublicKey(PublicKey,AlgorithmPreferences)
     */
    public PublicKey getCorePublicKey(AlgorithmPreferences algorithmPreferences) throws IOException {
        clearReadFlags();
        PublicKey publicKey = JSONSignatureDecoder.decodePublicKey(this, algorithmPreferences);
        checkForUnread();
        return publicKey;
    }

    /**
     * Read a public and private key in <a href="https://tools.ietf.org/html/rfc7517" target="_blank"><b>JWK</b></a> format.<p>
     * Note: this method assumes that the current object only holds a JWK key structure.</p>
     * 
     * @param algorithmPreferences JOSE or SKS notation expected
     * @return Java <code>KeyPair</code>
     * @throws IOException &nbsp;
     */
    public KeyPair getKeyPair(AlgorithmPreferences algorithmPreferences) throws IOException {
        clearReadFlags();
        PublicKey publicKey = JSONSignatureDecoder.decodePublicKey(this, algorithmPreferences);
        KeyPair keyPair = new KeyPair(publicKey, JSONSignatureDecoder.decodePrivateKey(this, publicKey));
        checkForUnread();
        return keyPair;
    }

    /**
     * Read a public and private key in <a href="https://tools.ietf.org/html/rfc7517" target="_blank"><b>JWK</b></a> format.<p>
     * Note: this method assumes that the current object only holds a JWK key structure.</p>
     * This method is equivalent to <code>getKeyPair(AlgorithmPreferences.JOSE)</code>.
     * 
     * @return Java <code>KeyPair</code>
     * @throws IOException &nbsp;
     */
    public KeyPair getKeyPair() throws IOException {
        return getKeyPair(AlgorithmPreferences.JOSE);
    }

    /**
     * Read an object in
     * <a href="https://cyberphone.github.io/doc/security/jef.html" target="_blank"><b>JEF</b></a>
     * format.<p>
     * Note: this method assumes that the current object only holds a JEF structure.</p>
     * @param options Restrictions and requirements
     * @return An object which can be used to retrieve the original (unencrypted) data 
     * @throws IOException &nbsp;
     * @see org.webpki.json.JSONObjectWriter#createEncryptionObject(byte[],DataEncryptionAlgorithms,JSONEncrypter)
     * @see org.webpki.json.JSONCryptoHelper.Options
     */
    public JSONDecryptionDecoder getEncryptionObject(JSONCryptoHelper.Options options) throws IOException {
        options.encryptionMode(true);
        if (hasProperty(JSONCryptoHelper.RECIPIENTS_JSON)) {
            throw new IOException("Please use \"getEncryptionObjects()\" for multiple encryption objects");
        }
        boolean keyEncryption = hasProperty(JSONCryptoHelper.ENCRYPTED_KEY_JSON);
        JSONDecryptionDecoder.Holder holder = new JSONDecryptionDecoder.Holder(options, this, keyEncryption);
        return new JSONDecryptionDecoder(holder, 
                                         keyEncryption ? getObject(JSONCryptoHelper.ENCRYPTED_KEY_JSON) : this,
                                         true);
    }

    /**
     * Read an object in
     * <a href="https://cyberphone.github.io/doc/security/jef.html" target="_blank"><b>JEF</b></a>
     * format intended for <i>multiple recipients</i>.<p>
     * Note: this method assumes that the current object only holds a JEF structure.</p>
     * @param options Global restrictions and requirements
     * @return An object which can be used to retrieve the original (unencrypted) data 
     * @throws IOException &nbsp;
     * @see org.webpki.json.JSONObjectWriter#createEncryptionObject(byte[],DataEncryptionAlgorithms,JSONEncrypter)
     * @see org.webpki.json.JSONCryptoHelper.Options
     */
    public Vector<JSONDecryptionDecoder> getEncryptionObjects(JSONCryptoHelper.Options options) throws IOException {
        options.encryptionMode(true);
        JSONDecryptionDecoder.Holder holder = new JSONDecryptionDecoder.Holder(options, this, true);
        JSONArrayReader recipientObjects = getArray(JSONCryptoHelper.RECIPIENTS_JSON);
        Vector<JSONDecryptionDecoder> recipients = new Vector<JSONDecryptionDecoder>();
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
     * <a href="https://cyberphone.github.io/doc/security/jcs.html" target="_blank"><b>JCS</b></a>
     * format.
     * <p>The array elements (base64url encoded certificates),
     * <b>must</b> be supplied in <i>strict issuance order</i>
     * where certificate[i] is signed by certificate[i + 1].</p>
     * @return Certificate path
     * @throws IOException &nbsp;
     * @see org.webpki.json.JSONObjectWriter#setCertificatePath(X509Certificate[])
     */
    public X509Certificate[] getCertificatePath() throws IOException {
        return getArray(JSONCryptoHelper.CERTIFICATE_PATH).getCertificatePath();
    }

    /**
     * Scan a property.
     * This method scans a property regardless of its type and it useful for dealing with
     * data where the type is unknown.
     * It also marks the property as "read" including possible child objects and arrays. 
     * @param name Property
     * @return Current instance of {@link org.webpki.json.JSONObjectReader}
     * @throws IOException &nbsp;
     * @see JSONObjectReader#checkForUnread()
     * @see JSONObjectReader#getPropertyType(String)
     * @see JSONObjectReader#getProperties()
     */
    public JSONObjectReader scanAway(String name) throws IOException {
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
     * @throws IOException &nbsp;
     */
    public JSONObjectReader removeProperty(String name) throws IOException {
        getProperty(name);
        root.properties.remove(name);
        return this;
    }

    /**
     * Serialize object reader to a Java <code>byte[]</code>.
     * @param outputFormat Any JSONOutputFormats
     * @return JSON string data
     * @throws IOException &nbsp;
     */
    public byte[] serializeToBytes(JSONOutputFormats outputFormat) throws IOException {
        return new JSONObjectWriter(root).serializeToBytes(outputFormat);
    }

    /**
     * Serialize object reader to a Java <code>String</code>.
     * @param outputFormat Any JSONOutputFormats
     * @return JSON string data
     * @throws IOException &nbsp;
     */
     public String serializeToString(JSONOutputFormats outputFormat) throws IOException {
        return new JSONObjectWriter(root).serializeToString(outputFormat);
    }

    /**
     * Deep copy of JSON object reader.
     */
    @Override
    public JSONObjectReader clone() {
        try {
            return JSONParser.parse(serializeToBytes(JSONOutputFormats.NORMALIZED));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Pretty print JSON of object reader.
     */
    @Override
    public String toString() {
        return new JSONObjectWriter(root).toString();
    }
}
