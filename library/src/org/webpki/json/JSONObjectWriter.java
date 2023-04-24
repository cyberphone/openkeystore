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
package org.webpki.json;

import java.io.IOException;

import java.math.BigDecimal;
import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.ECPoint;

import java.util.EnumSet;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.TreeSet;
import java.util.ArrayList;

import java.util.regex.Pattern;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.OkpSupport;
import org.webpki.crypto.KeyAlgorithms;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;
import org.webpki.util.ISODateTime;
import org.webpki.util.UTF8;

/**
 * Creates JSON objects and performs serialization
 * using a variety of formats.
 * <p>
 * Also provides built-in support for encoding
 * <a href="https://cyberphone.github.io/doc/security/jsf.html" 
 * target="_blank"><b>JSF (JSON Signature Format)</b></a>, 
 * <a href="https://cyberphone.github.io/doc/security/jef.html" 
 * target="_blank"><b>JEF (JSON Encryption Format)</b></a>
 * and
 * <a href="https://tools.ietf.org/html/rfc7517" target="_blank"><b>JWK</b></a>
 * objects.</p>
 */
public class JSONObjectWriter {

    static final int STANDARD_INDENT = 2;
    
    /**
     * Integers outside of this range are not natively supported by I-JSON/JavaScript.
     */
    public static final long MAX_INTEGER  = 9007199254740992L; // 2^53 ("53-bit precision")

    static final Pattern JS_ID_PATTERN    = Pattern.compile("[a-zA-Z$_]+[a-zA-Z$_0-9]*");

    public static final String SIGNATURE_DEFAULT_LABEL_JSON = "signature";  // Not a part of the SPEC

    JSONObject root;

    StringBuilder buffer;

    int indent;

    boolean prettyPrint;

    boolean javaScriptMode;

    boolean htmlMode;
    
    boolean canonicalized;

    int indentFactor;

    static String htmlVariableColor = "#008000";
    static String htmlStringColor   = "#0000C0";
    static String htmlPropertyColor = "#C00000";
    static String htmlKeywordColor  = "#606060";

    static int htmlIndent = 4;

    /**
     * Support interface for dynamic JSON generation.
     */
    public interface Dynamic {

        public JSONObjectWriter set(JSONObjectWriter wr) throws IOException;

    }

    /**
     * For updating already read JSON objects.
     *
     * @param objectReader Existing object reader
     * @throws IOException For any kind of underlying error...
     */
    public JSONObjectWriter(JSONObjectReader objectReader) throws IOException {
        this(objectReader.root);
        if (objectReader.root.properties.containsKey(null)) {
            throw new IOException("You cannot update array objects");
        }
    }

    /**
     * Creates a fresh JSON object and associated writer.
     */
    public JSONObjectWriter() {
        this(new JSONObject());
    }

    JSONObjectWriter(JSONObject root) {
        this.root = root;
    }

    JSONObjectWriter setProperty(String name, JSONValue value) throws IOException {
        root.setProperty(name, value);
        value.preSet = true;
        return this;
    }

    /**
     * Prepares the current object writer for a <i>rewrite</i> of a property.
     * @param name Name of property to be rewritten
     */
    public void setupForRewrite(String name) {
        root.properties.put(name, null);
    }

    /**
     * Set a <code>"string"</code> property.<p>
     * Sample:
     * <pre>
     *    "statement": "Life is good!"
     * </pre>
     * @param name Property
     * @param value Value
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     */
    public JSONObjectWriter setString(String name, String value) throws IOException {
        return setProperty(name, new JSONValue(JSONTypes.STRING, value));
    }

    static String serializeLong(long value) throws IOException {
        return Long.toString(JSONObjectReader.int53Check(value));
    }

    /**
     * Set an <code>int</code> property.<p>
     * Sample:
     * <pre>
     *    "headCount": 300
     * </pre>
     * @param name Property
     * @param value Value
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     */
    public JSONObjectWriter setInt(String name, int value) throws IOException {
        return setInt53(name, value);
    }

    /**
     * Set a <code>long</code> property.<p>
     * Sample:</p>
     * <p><code>&nbsp;&nbsp;&nbsp;&nbsp;"quiteNegative": -800719925474099</code>
     * </p> Note that <code>long</code> data is limited to 53 bits of precision ({@value #MAX_INTEGER}),
     * exceeding this limit throws an exception.
     * If you need higher precision use {@link JSONObjectWriter#setLong(String, long)}.
     * @param name Property
     * @param value Value
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     * @see #MAX_INTEGER
     */
    public JSONObjectWriter setInt53(String name, long value) throws IOException {
        return setProperty(name, new JSONValue(JSONTypes.NUMBER, serializeLong(value)));
    }

    /**
     * Set a <code>long</code> property.<p>
     * Sample:</p>
     * <p><code>&nbsp;&nbsp;&nbsp;&nbsp;"quiteLong": "89007199254740991"</code>
     * </p>Note: This method puts the value within quotes to provide full 64-bit precision
     * which does not have a native counterpart in JavaScript.
     * @param name Property
     * @param value Value
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     * @see #setInt53(String, long)
     * @see #setBigInteger(String, BigInteger)
     */
    public JSONObjectWriter setLong(String name, long value) throws IOException {
        return setBigInteger(name, BigInteger.valueOf(value));
    }

    /**
     * Set a <code>double</code> property.<p>
     * Sample:
     * <pre>
     *    "Planck's Constant": 6.62607004e-34
     * </pre>
     * @param name Property
     * @param value Value
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     */
    public JSONObjectWriter setDouble(String name, double value) throws IOException {
        return setProperty(name, 
                           new JSONValue(JSONTypes.NUMBER, 
                           NumberToJSON.serializeNumber(value)));
    }

    /**
     * Set a <code>BigInteger</code> property.<p>
     * Note: this is a <i>mapped</i> type since there is no <code>BigInteger</code> type in JSON.</p><p>
     * Sample:
     * <pre>
     *    "aPrettyHugeNumber": "94673335822222222222222222222222222222222222222222222"
     * </pre>
     * @param name Property
     * @param value Value
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     */
    public JSONObjectWriter setBigInteger(String name, BigInteger value) throws IOException {
        return setString(name, value.toString());
    }

    static String bigDecimalToString(BigDecimal value) {
        return value.toString().replace('E', 'e');
    }

    /**
     * Set a <code>BigDecimal</code> property.<p>
     * Note: this is a <i>mapped</i> type since there is no <code>BigDecimal</code> type in JSON.</p><p>
     * Sample:
     * <pre>
     *    "big": "56.67e+450"
     * </pre>
     * @param name Property
     * @param value Value
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     */
    public JSONObjectWriter setBigDecimal(String name, BigDecimal value) throws IOException {
        return setString(name, bigDecimalToString(value));
    }

    static String moneyToString(BigDecimal value, Integer decimals) {
        return (decimals == null ? value : value.setScale(decimals)).toPlainString();
    }

    /**
     * Set a <code>Money</code> property.<p>
     * Note: this is a <i>mapped</i> type since there is no <code>Money</code> type in JSON.</p>
     * <p>Specification: <a href="https://www.w3.org/TR/payment-request/#dfn-valid-decimal-monetary-value" 
     * target="_blank">https://www.w3.org/TR/payment-request/#dfn-valid-decimal-monetary-value</a>.</p>
     * Sample:
     * <pre>
     *    "amount": "460.25"
     * </pre>
     * @param name Property
     * @param value Value
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     * @see #setMoney(String, BigDecimal, int)
     */
    public JSONObjectWriter setMoney(String name, BigDecimal value) throws IOException {
        return setString(name, moneyToString(value, null));
    }

    /**
     * Set a <code>Money</code> property.<p>
     * Note: this is a <i>mapped</i> type since there is no <code>Money</code> type in JSON.</p>
     * <p>Specification: <a href="https://www.w3.org/TR/payment-request/#dfn-valid-decimal-monetary-value" 
     * target="_blank">https://www.w3.org/TR/payment-request/#dfn-valid-decimal-monetary-value</a>.</p>
     * Sample:
     * <pre>
     *    "amount": "460.25"
     * </pre>
     * @param name Property
     * @param value Value
     * @param decimals Number of fractional digits
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     * @see #setMoney(String, BigDecimal)
     */
    public JSONObjectWriter setMoney(String name, BigDecimal value, int decimals) 
            throws IOException {
        return setString(name, moneyToString(value, decimals));
    }

    /**
     * Set a <code>boolean</code> property.<p>
     * Sample:
     * <pre>
     *    "theEarthIsFlat": false
     * </pre>
     * @param name Property
     * @param value Value
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     */
    public JSONObjectWriter setBoolean(String name, boolean value) throws IOException {
        return setProperty(name, new JSONValue(JSONTypes.BOOLEAN, Boolean.toString(value)));
    }

    /**
     * Set a <b>null</b> property.<p>
     * Sample:
     * <pre>
     *    "myKnowledgeOfTheLispProgrammingLanguage": null
     * </pre>
     * @param name Property
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     * @see JSONObjectReader#getIfNULL(String)
     */
    public JSONObjectWriter setNULL(String name) throws IOException {
        return setProperty(name, new JSONValue(JSONTypes.NULL, "null"));
    }

    /**
     * Set an ISO formatted <code>dateTime</code> property.<p>
     * Note: this is a <i>mapped</i> type since there is no <code>dateTime</code> type in JSON.</p><p>
     * Sample:
     * <pre>
     *    "received": "2016-11-12T09:22:36Z"
     * </pre>
     * @param name Property
     * @param dateTime Date/time value
     * @param format Requited output format
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     * @see org.webpki.util.ISODateTime#encode(GregorianCalendar, EnumSet)
     */
    public JSONObjectWriter setDateTime(String name, 
                                        GregorianCalendar dateTime,
                                        EnumSet<ISODateTime.DatePatterns> format) throws IOException {
        return setString(name, ISODateTime.encode(dateTime, format));
    }

    /**
     * Set a <code>byte[]</code> property.<p>
     * This method utilizes Base64Url encoding.</p><p>
     * Sample:
     * <pre>
     *    "nonce": "lNxNvAUEE8t7DSQBft93LVSXxKCiVjhbWWfyg023FCk"
     * </pre>
     * @param name Property
     * @param value Array of bytes
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     * @see Base64URL#encode(byte[])
     */
    public JSONObjectWriter setBinary(String name, byte[] value) throws IOException {
        return setString(name, Base64URL.encode(value));
    }

    /**
     * Set a JSON object.<p>
     * This method assigns a property name to an already existing object reader
     * which is useful for wrapping JSON objects.</p>
     * @param name Property
     * @param objectReader Object reader
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     */
    public JSONObjectWriter setObject(String name, JSONObjectReader objectReader) throws IOException {
        setProperty(name, new JSONValue(JSONTypes.OBJECT, objectReader.root));
        return this;
    }

    /**
     * Set a JSON object.<p>
     * This method assigns a property name to an already created object writer
     * which is useful for nested JSON objects.</p>
     * @param name Property
     * @param objectWriter Object writer
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     */
    public JSONObjectWriter setObject(String name, JSONObjectWriter objectWriter) throws IOException {
        setProperty(name, new JSONValue(JSONTypes.OBJECT, objectWriter.root));
        return this;
    }

    /**
     * Set (create) a JSON object.<p>
     * This method creates an empty JSON object and links it to the current object through a property.</p> 
     * @param name Property
     * @return New instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     */
    public JSONObjectWriter setObject(String name) throws IOException {
        JSONObjectWriter writer = new JSONObjectWriter();
        setProperty(name, new JSONValue(JSONTypes.OBJECT, writer.root));
        return writer;
    }

    /**
     * Set (create) a JSON array.<p>
     * This method creates an empty JSON array and links it to the current object through a property.</p> 
     * @param name Property
     * @return New instance of {@link org.webpki.json.JSONArrayWriter}
     * @throws IOException
     */
    public JSONArrayWriter setArray(String name) throws IOException {
        JSONArrayWriter array = new JSONArrayWriter();
        setProperty(name, new JSONValue(JSONTypes.ARRAY, array.array));
        return array;
    }

    /**
     * Set a JSON array.<p>
     * This method assigns a property name to an already created array writer
     * which is useful for nested JSON objects.</p>
     * @param name Property
     * @param arrayWriter Array writer
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     */
    public JSONObjectWriter setArray(String name, JSONArrayWriter arrayWriter) throws IOException {
        setProperty(name, new JSONValue(JSONTypes.ARRAY, arrayWriter.array));
        return this;
    }

    JSONObjectWriter setStringArray(String name, String[] values, JSONTypes jsonType) throws IOException {
        ArrayList<JSONValue> array = new ArrayList<>();
        for (String value : values) {
            array.add(new JSONValue(jsonType, value));
        }
        return setProperty(name, new JSONValue(JSONTypes.ARRAY, array));
    }

    /**
     * Set an array of <code>byte[]</code> property.<p>
     * This method puts each byte array (after Base64Url encoding) into a single JSON array.</p><p>
     * Sample:
     * <pre>
     *    "blobs": ["lNxNvAUEE8t7DSQBft93LVSXxKCiVjhbWWfyg023FCk","LmTlQxXB3LgZrNLmhOfMaCnDizczC_RfQ6Kx8iNwfFA"]
     * </pre>
     * @param name Property
     * @param values List holding arrays of bytes
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     * @see Base64URL#encode(byte[])
     */
    public JSONObjectWriter setBinaryArray(String name, List<byte[]> values) throws IOException {
        ArrayList<String> array = new ArrayList<>();
        for (byte[] value : values) {
            array.add(Base64URL.encode(value));
        }
        return setStringArray(name, array.toArray(new String[0]));
    }

    /**
     * Set a <code>String[]</code> property.<p>
     * This method puts each <code>String</code> into a single JSON array.</p><p>
     * Sample:
     * <pre>
     *    "usPresidents": ["Clinton","Bush","Obama","Trump"]
     * </pre>
     * @param name Property
     * @param values Array of <code>String</code>
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     */
    public JSONObjectWriter setStringArray(String name, String[] values) throws IOException {
        return setStringArray(name, values, JSONTypes.STRING);
    }

    /**
     * Set JSON data using an external (dynamic) interface.<p>
     * Sample using a construct suitable for chained writing:
     * <pre>
     *    setDynamic((wr) -&gt; optionalString == null ? wr : wr.setString("opt", optionalString)); 
     * </pre>
     * @param jsonSetDynamic Interface (usually Lambda)
     * @return An instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     */
    public JSONObjectWriter setDynamic(Dynamic jsonSetDynamic) throws IOException {
        return jsonSetDynamic.set(this);
    }

    /**
     * Copy arbitrary JSON data from a {@link org.webpki.json.JSONObjectReader}
     * 
     * @param newName Property name in the current object
     * @param sourceName Property name in the source object
     * @param source The JSON reader object
     * @return An instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     */
    public JSONObjectWriter copyElement(String newName, 
                                        String sourceName,
                                        JSONObjectReader source) throws IOException {
        return setProperty(newName, source.getProperty(sourceName));
    }

    void setCurvePoint(BigInteger value, String name, KeyAlgorithms ec) throws IOException {
        byte[] curvePoint = value.toByteArray();
        if (curvePoint.length > (ec.getPublicKeySizeInBits() + 7) / 8) {
            if (curvePoint[0] != 0) {
                throw new IOException("Unexpected EC \"" + name + "\" value");
            }
            setCryptoBinary(value, name);
        } else {
            while (curvePoint.length < (ec.getPublicKeySizeInBits() + 7) / 8) {
                curvePoint = ArrayUtil.add(new byte[]{0}, curvePoint);
            }
            setBinary(name, curvePoint);
        }
    }

    void setCryptoBinary(BigInteger value, String name) throws IOException {
        byte[] cryptoBinary = value.toByteArray();
        if (cryptoBinary[0] == 0x00) {
            byte[] woZero = new byte[cryptoBinary.length - 1];
            System.arraycopy(cryptoBinary, 1, woZero, 0, woZero.length);
            cryptoBinary = woZero;
        }
        setBinary(name, cryptoBinary);
    }

    static void coreSign(JSONSigner signer, 
                         JSONObjectWriter innerObject,
                         JSONObjectWriter outerObject,
                         JSONObjectWriter signedObject) throws IOException,
                                                               GeneralSecurityException {

        innerObject.setString(JSONCryptoHelper.ALGORITHM_JSON,
                              signer.getAlgorithm().getAlgorithmId(signer.algorithmPreferences));
        
        if (signer.keyId != null) {
            innerObject.setString(JSONCryptoHelper.KEY_ID_JSON, signer.keyId);
        }

        signer.writeKeyData(innerObject);
        
        // Optional extensions
        if (signer.extensionData != null) {
            if (signer.extensionNames == null) {
                throw new IOException("Missing call to \"setExtensionNames()\"");
            }
            outerObject.setStringArray(JSONCryptoHelper.EXTENSIONS_JSON,
                                       signer.extensionNames.toArray(new String[0]));
            for (String property : signer.extensionData.getProperties()) {
                if (!signer.extensionNames.contains(property)) {
                    throw new IOException("Undeclared extension: \"" + property + "\"");
                }
                innerObject.setProperty(property, signer.extensionData.getProperty(property));
            }
        }

        // Optional excluded properties
        if (signer.excluded != null) {
            JSONObjectReader rd = new JSONObjectReader(signedObject).clone();
            for (String property : signer.excluded) {
                if (!rd.hasProperty(property)) {
                    throw new IOException("Missing \"" + 
                                          JSONCryptoHelper.EXCLUDES_JSON + 
                                          "\" property: " + property);
                }
                rd.removeProperty(property);
            }
            signedObject = new JSONObjectWriter(rd);
            outerObject.setStringArray(JSONCryptoHelper.EXCLUDES_JSON, signer.excluded);
        }

        // Finally, the signature itself
        innerObject.setBinary(JSONCryptoHelper.VALUE_JSON,
                              signer.signData(signer.normalizedData = 
                                  signedObject.serializeToBytes(JSONOutputFormats.CANONICALIZED)));
    }

    /**
     * Set a <a href="https://cyberphone.github.io/doc/security/jsf.html" target="_blank"><b>JSF</b></a>
     * <code>"signature"</code>object.<p>
     * This method performs all the processing needed for adding a JSF signature to the current object.</p>
     * @param signer The interface to the signing key and type
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException In case there a problem with keys etc.
     * <br>&nbsp;<br><b>Sample Code:</b>
     <pre>
import java.io.IOException;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.SignatureWrapper;

import org.webpki.json.JSONAsymKeySigner;
import org.webpki.json.JSONAsymKeyVerifier;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONSignatureDecoder;
           .
           .
           .
    public void signAndVerifyJSF(PrivateKey privateKey, PublicKey publicKey) throws IOException {
    
        // Create an empty JSON document
        JSONObjectWriter writer = new JSONObjectWriter();
    
        // Fill it with some data
        writer.setString("myProperty", "Some data");
    
        // Sign document
        writer.setSignature(new JSONAsymKeySigner(privateKey, publicKey, null));

        // Serialize document
        String json = writer.toString();
    
        // Print signed document on the console
        System.out.println(json);
</pre>
<div id="verify" style="display:inline-block;background:#F8F8F8;border-width:1px;border-style:solid;border-color:grey;padding:0pt 10pt 0pt 10pt;box-shadow:3pt 3pt 3pt #D0D0D0"><pre>{
  "<span style="color:#C00000">myProperty</span>": "<span style="color:#0000C0">Some data</span>",
  "<span style="color:#C00000">signature</span>": {
    "<span style="color:#C00000">algorithm</span>": "<span style="color:#0000C0">ES256</span>",
    "<span style="color:#C00000">publicKey</span>": {
      "<span style="color:#C00000">kty</span>": "<span style="color:#0000C0">EC</span>",
      "<span style="color:#C00000">crv</span>": "<span style="color:#0000C0">P-256</span>",
      "<span style="color:#C00000">x</span>": "<span style="color:#0000C0">PxlJQu9Q6dOvM4LKoZUh2XIe9-pdcLkvKfBfQk11Sb0</span>",
      "<span style="color:#C00000">y</span>": "<span style="color:#0000C0">6IDquxrbdq5ABe4-HQ78_dhM6eEBUbvDtdqK31YfRP8</span>"
    },
    "<span style="color:#C00000">value</span>": "<span style="color:#0000C0">vHXWLfhmkl2qk3Eo5gwBFJy68RFMCJziviO8QkUAwarjNL4yrd5VGbYnYzoVLWj50up5A908_8eVDt_W0xJo7g</span>"
  }
}
</pre></div>    
<pre>
        // Parse document
        JSONObjectReader reader = JSONParser.parse(json);
    
        // Get and verify signature
        JSONSignatureDecoder signature = reader.getSignature(new JSONCryptoHelper.Options());
        signature.verify(new JSONAsymKeyVerifier(publicKey));
    
        // Print document payload on the console
        System.out.println("Returned data: " + reader.getString("myProperty"));
    }
</pre>
     * @throws GeneralSecurityException 
    */
    public JSONObjectWriter setSignature(JSONSigner signer)
            throws IOException, GeneralSecurityException {
        return setSignature(SIGNATURE_DEFAULT_LABEL_JSON, signer);
    }
    
    public JSONObjectWriter setSignature(String signatureLabel, JSONSigner signer)
            throws IOException, GeneralSecurityException {
        JSONObjectWriter signatureObject = setObject(signatureLabel);
        coreSign(signer, signatureObject, signatureObject, this);
        return this;
    }
    
    JSONObjectWriter setSignatureArrayElement(String signatureLabel,
                                              JSONSigner signer,
                                              boolean chained) throws IOException,
                                                                      GeneralSecurityException {       
        JSONObjectReader reader = new JSONObjectReader(root);
        ArrayList<JSONObject> oldSignatures = new ArrayList<>();
        String keyWord = chained ? JSONCryptoHelper.CHAIN_JSON : JSONCryptoHelper.SIGNERS_JSON;
        if (reader.hasProperty(signatureLabel)) {
            reader = reader.getObject(signatureLabel);
            if (signer.extensionNames != null) {
                throw new IOException("Only the first signer can set \"" + 
                                      JSONCryptoHelper.EXTENSIONS_JSON + "\"");
            }
            if (signer.excluded != null) {
                throw new IOException("Only the first signer can set \"" + 
                                      JSONCryptoHelper.EXCLUDES_JSON + "\"");
            }
            JSONArrayReader signatureArray = reader.getArray(keyWord);
            do {
                oldSignatures.add(signatureArray.getObject().root);
            } while (signatureArray.hasMore());
            if (reader.hasProperty(JSONCryptoHelper.EXCLUDES_JSON)) {
                signer.setExcluded(reader.getStringArray(JSONCryptoHelper.EXCLUDES_JSON));
            }
            if (reader.hasProperty(JSONCryptoHelper.EXTENSIONS_JSON)) {
                signer.setExtensionNames(reader.getStringArray(JSONCryptoHelper.EXTENSIONS_JSON));
            }
            setupForRewrite(signatureLabel);
        }
        JSONObjectWriter globalSignatureObject = setObject(signatureLabel);
        JSONArrayWriter signatureArray = globalSignatureObject.setArray(keyWord);
        if (!chained) {
            coreSign(signer, signatureArray.setObject(), globalSignatureObject, this);
        }
        int q = oldSignatures.size();
        while (--q >= 0) {
            signatureArray.array.add(0, new JSONValue(JSONTypes.OBJECT, oldSignatures.get(q)));
        }
        if (chained) {
            coreSign(signer, signatureArray.setObject(), globalSignatureObject, this);
        }
        /*
        if (multiSignatureHeader.optionalFormatVerifier != null) {
            new JSONObjectReader(root).getMultiSignature(signatureLabel, multiSignatureHeader.optionalFormatVerifier);
        }
        */
        return this;
    }

    /**
     * Set a <a href="https://cyberphone.github.io/doc/security/jsf.html" target="_blank"><b>JSF</b></a>
     * multi-signature object.<p>
     * This method performs all the processing needed for adding multiple JSF signatures to the current object.</p>
     * @param signer Signature interface
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException In case there a problem with keys etc.
     * @throws GeneralSecurityException 
     */
    public JSONObjectWriter setMultiSignature(JSONSigner signer) throws IOException,
                                                                        GeneralSecurityException {
        return setMultiSignature(SIGNATURE_DEFAULT_LABEL_JSON, signer);
    }

    public JSONObjectWriter setMultiSignature(String signatureLabel,
                                              JSONSigner signer) throws IOException,
                                                                        GeneralSecurityException {
        return setSignatureArrayElement(signatureLabel, signer, false);
    }

    /**
     * Set a <a href="https://cyberphone.github.io/doc/security/jsf.html" target="_blank"><b>JSF</b></a>
     * chained-signature object.<p>
     * This method performs all the processing needed for adding multiple JSF signatures to the current object.</p>
     * @param signer Signature interface
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException In case there a problem with keys etc.
     * @throws GeneralSecurityException 
     */
    public JSONObjectWriter setChainedSignature(JSONSigner signer) throws IOException,
                                                                          GeneralSecurityException {
        return setChainedSignature(SIGNATURE_DEFAULT_LABEL_JSON, signer);
    }

    public JSONObjectWriter setChainedSignature(String signatureLabel,
                                                JSONSigner signer) throws IOException,
                                                                          GeneralSecurityException {
        return setSignatureArrayElement(signatureLabel, signer, true);
    }

    /**
     * Create a <a href="https://cyberphone.github.io/doc/security/jsf.html" target="_blank">JSF</a>
     * (<a href="https://tools.ietf.org/html/rfc7517" target="_blank"><b>JWK</b></a>) formatted public key.<p>
     * Typical use:
     *<pre>
    setObject("myPublicKey", JSONObjectWriter.setCorePublicKey(myPublicKey, AlgorithmPreferences.JOSE);
</pre>
     * Resulting JSON:
     * <pre>
    "myPublicKey": {
         .
      <i>depends on the actual public key type and value</i>   
         .
    }
</pre>
     * @param publicKey Public key value
     * @param algorithmPreferences JOSE or SKS algorithm notation
     * @return New instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     */
    public static JSONObjectWriter createCorePublicKey(PublicKey publicKey, 
                                                       AlgorithmPreferences algorithmPreferences)
    throws IOException {
        JSONObjectWriter corePublicKey = new JSONObjectWriter();
        KeyAlgorithms keyAlg = KeyAlgorithms.getKeyAlgorithm(publicKey);
        corePublicKey.setString(JSONCryptoHelper.KTY_JSON, keyAlg.getKeyType().getJoseKty());
        switch (keyAlg.getKeyType()) {
            case RSA:
                RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
                corePublicKey.setCryptoBinary(rsaPublicKey.getModulus(), JSONCryptoHelper.N_JSON);
                corePublicKey.setCryptoBinary(rsaPublicKey.getPublicExponent(), 
                                              JSONCryptoHelper.E_JSON);
                break;
            case EC:
                corePublicKey.setString(JSONCryptoHelper.CRV_JSON, 
                                        keyAlg.getAlgorithmId(algorithmPreferences));
                ECPoint ecPoint = ((ECPublicKey) publicKey).getW();
                corePublicKey.setCurvePoint(ecPoint.getAffineX(), JSONCryptoHelper.X_JSON, keyAlg);
                corePublicKey.setCurvePoint(ecPoint.getAffineY(), JSONCryptoHelper.Y_JSON, keyAlg);
                break;
            default:  // EDDSA and XEC
                corePublicKey.setString(JSONCryptoHelper.CRV_JSON, 
                                        keyAlg.getAlgorithmId(algorithmPreferences));
                corePublicKey.setBinary(JSONCryptoHelper.X_JSON,
                                        OkpSupport.public2RawKey(publicKey, keyAlg));
        }
        return corePublicKey;
    }

    /**
     * Set a <a href="https://cyberphone.github.io/doc/security/jsf.html" target="_blank">JSF</a>
     * (<a href="https://tools.ietf.org/html/rfc7517" target="_blank"><b>JWK</b></a>) formatted public key.<p>
     * Resulting JSON:
     * <pre>
    "publicKey": {
         .
      <i>depends on the actual public key type and value</i>   
         .
    }
</pre>
     * @param publicKey Public key value
     * @param algorithmPreferences JOSE or SKS algorithm notation
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     */
    public JSONObjectWriter setPublicKey(PublicKey publicKey, 
                                         AlgorithmPreferences algorithmPreferences)
    throws IOException {
        return setObject(JSONCryptoHelper.PUBLIC_KEY_JSON, 
                         createCorePublicKey(publicKey, algorithmPreferences));
    }

    /**
     * Set a <a href="https://cyberphone.github.io/doc/security/jsf.html" target="_blank">JSF</a>
     * (<a href="https://tools.ietf.org/html/rfc7517" target="_blank"><b>JWK</b></a>) formatted public key.<p>
     * This method is equivalent to {@link #setPublicKey(PublicKey, AlgorithmPreferences)}
     * using {@link AlgorithmPreferences#JOSE} as second argument.</p>
     * @param publicKey Public key value
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     */
    public JSONObjectWriter setPublicKey(PublicKey publicKey) throws IOException {
        return setPublicKey(publicKey, AlgorithmPreferences.JOSE);
    }

    /**
     * Set a <a href="https://cyberphone.github.io/doc/security/jsf.html" target="_blank"><b>JSF</b></a>
     * certificate path property.
     * <p>Each path element (certificate) is base64url encoded and the path must be
     * <i>sorted</i> where certificate[i] is signed by certificate[i + 1].</p><p>
     * Resulting JSON:
     * <pre>
    "certificatePath": ["MIIETTCCAjWgAwIBAgIGAUoqo74...gfdd" {,...}]
</pre>
     * @param certificatePath Sorted certificate path array
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     */
    public JSONObjectWriter setCertificatePath(X509Certificate[] certificatePath) 
    throws IOException, GeneralSecurityException {
        return setArray(JSONCryptoHelper.CERTIFICATE_PATH_JSON, 
                        JSONArrayWriter.createCoreCertificatePath(certificatePath));
    }

    /**
     * Create a <a href="https://cyberphone.github.io/doc/security/jef.html" target="_blank"><b>JEF</b></a>
     * encrypted object.
     * @param unencryptedData Data to be encrypted
     * @param contentEncryptionAlgorithm Content encryption algorithm
     * @param encrypter Holds keys etc.
     * @return New instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static JSONObjectWriter 
            createEncryptionObject(byte[] unencryptedData,
                                   ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                                   JSONEncrypter encrypter)
    throws IOException, GeneralSecurityException {
        JSONEncrypter.Header header = 
                new JSONEncrypter.Header(contentEncryptionAlgorithm, encrypter);
        JSONObjectWriter encryptionObject = header.encryptionWriter;
        if (encrypter.keyEncryptionAlgorithm != null) {
            encryptionObject = encryptionObject.setObject(JSONCryptoHelper.KEY_ENCRYPTION_JSON);
        }
        header.createRecipient(encrypter, encryptionObject);
        return header.finalizeEncryption(unencryptedData);
    }

    /**
     * Create a <a href="https://cyberphone.github.io/doc/security/jef.html" target="_blank"><b>JEF</b></a>
     * encrypted object for multiple recipients.
     * @param unencryptedData Data to be encrypted
     * @param contentEncryptionAlgorithm Content encryption algorithm
     * @param encrypters Holds keys etc.
     * @return New instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static JSONObjectWriter 
            createEncryptionObjects(byte[] unencryptedData,
                                    ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                                    List<JSONEncrypter> encrypters)
    throws IOException, GeneralSecurityException {
        if (encrypters.isEmpty()) {
            throw new IOException("Empty encrypter list");
        }
        JSONEncrypter.Header header = 
                new JSONEncrypter.Header(contentEncryptionAlgorithm, encrypters.get(0));
        JSONArrayWriter recipientList = 
                header.encryptionWriter.setArray(JSONCryptoHelper.RECIPIENTS_JSON);
        for (JSONEncrypter encrypter : encrypters) {
            JSONDecryptionDecoder.keyWrapCheck(encrypter.keyEncryptionAlgorithm);
            JSONObjectWriter recipient = new JSONObjectWriter();
            header.createRecipient(encrypter, recipient);
            recipientList.setObject(recipient);
        }
        return header.finalizeEncryption(unencryptedData);
    }    


    ////////////////////////////////////////////////////////////////////////
    
    void newLine() {
        if (prettyPrint) {
            buffer.append(htmlMode ? "<br>" : "\n");
        }
    }

    void indentLine() {
        indent += indentFactor;
    }

    void undentLine() {
        indent -= indentFactor;
    }

    @SuppressWarnings("unchecked")
    void printOneElement(JSONValue jsonValue) throws IOException {
        switch (jsonValue.type) {
            case ARRAY:
                printArray((ArrayList<JSONValue>) jsonValue.value);
                break;

            case OBJECT:
                printObject((JSONObject) jsonValue.value);
                break;

            default:
                printSimpleValue(jsonValue, false);
        }
    }

    void newUndentSpace() {
        newLine();
        undentLine();
        spaceOut();
    }

    void newIndentSpace() {
        newLine();
        indentLine();
        spaceOut();
    }

    void printObject(JSONObject object) throws IOException {
        buffer.append('{');
        indentLine();
        boolean next = false;
        for (String property : canonicalized ? 
                new TreeSet<>(object.properties.keySet()) : object.properties.keySet()) {
            JSONValue jsonValue = object.properties.get(property);
            if (jsonValue == null) {
                continue;
            }
            if (next) {
                buffer.append(',');
            }
            newLine();
            next = true;
            printProperty(property);
            printOneElement(jsonValue);
        }
        newUndentSpace();
        buffer.append('}');
    }

    @SuppressWarnings("unchecked")
    void printArray(ArrayList<JSONValue> array) throws IOException {
        buffer.append('[');
        if (!array.isEmpty()) {
            boolean mixed = false;
            JSONTypes firstType = array.get(0).type;
            for (JSONValue jsonValue : array) {
                if (firstType.complex != jsonValue.type.complex ||
                        (firstType.complex && firstType != jsonValue.type))

                {
                    mixed = true;
                    break;
                }
            }
            if (mixed || (array.size() == 1 && firstType == JSONTypes.OBJECT)) {
                boolean next = false;
                for (JSONValue value : array) {
                    if (next) {
                        buffer.append(',');
                    } else {
                        next = true;
                    }
                    printOneElement(value);
                }
            } else if (firstType == JSONTypes.OBJECT) {
                printArrayObjects(array);
            } else if (firstType == JSONTypes.ARRAY) {
                newIndentSpace();
                boolean next = false;
                for (JSONValue value : array) {
                    ArrayList<JSONValue> subArray = (ArrayList<JSONValue>) value.value;
                    if (next) {
                        buffer.append(',');
                    } else {
                        next = true;
                    }
                    printArray(subArray);
                }
                newUndentSpace();
            } else {
                printArraySimple(array);
            }
        }
        buffer.append(']');
    }

    void printArraySimple(ArrayList<JSONValue> array) throws IOException {
        int i = 0;
        for (JSONValue value : array) {
            i += ((String) value.value).length();
        }
        boolean brokenLines = i > 100;
        boolean next = false;
        if (brokenLines) {
            indentLine();
            newLine();
        }
        for (JSONValue value : array) {
            if (next) {
                buffer.append(',');
                if (brokenLines) {
                    newLine();
                } else {
                    singleSpace();
                }
            }
            if (brokenLines) {
                spaceOut();
            }
            printSimpleValue(value, false);
            next = true;
        }
        if (brokenLines) {
            newUndentSpace();
        }
    }

    void printArrayObjects(ArrayList<JSONValue> array) throws IOException {
        boolean next = false;
        for (JSONValue value : array) {
            if (next) {
                buffer.append(',');
            }
            printObject((JSONObject) value.value);
            next = true;
        }
    }

    @SuppressWarnings("fallthrough")
    void printSimpleValue(JSONValue value, boolean property) throws IOException {
        String string = (String) value.value;
        if (value.type != JSONTypes.STRING) {
            if (htmlMode) {
                buffer.append("<span style=\"color:")
                        .append(htmlVariableColor)
                        .append("\">");
            }
            buffer.append(value.type != JSONTypes.NUMBER || value.preSet ? 
                    string : NumberToJSON.serializeNumber(Double.valueOf(string)));

            if (htmlMode) {
                buffer.append("</span>");
            }
            return;
        }
        boolean quoted = !property || !javaScriptMode || !JS_ID_PATTERN.matcher(string).matches();
        if (htmlMode) {
            buffer.append("&quot;<span style=\"color:")
                    .append(property ? string.startsWith("@") ? 
                            htmlKeywordColor : htmlPropertyColor : htmlStringColor)
                    .append("\">");
        } else if (quoted) {
            buffer.append('"');
        }
        for (char c : string.toCharArray()) {
            if (htmlMode) {
                switch (c) {
/* 
      HTML needs specific escapes...
*/
                    case '<':
                        buffer.append("&lt;");
                        continue;

                    case '>':
                        buffer.append("&gt;");
                        continue;

                    case '&':
                        buffer.append("&amp;");
                        continue;

                    case '"':
                        buffer.append("\\&quot;");
                        continue;
                }
            }

            switch (c) {
                case '\\':
                case '"':
                    escapeCharacter(c);
                    break;

                case '\b':
                    escapeCharacter('b');
                    break;

                case '\f':
                    escapeCharacter('f');
                    break;

                case '\n':
                    escapeCharacter('n');
                    break;

                case '\r':
                    escapeCharacter('r');
                    break;

                case '\t':
                    escapeCharacter('t');
                    break;

                default:
                    if (c < 0x20) {
                        escapeCharacter('u');
                        for (int i = 0; i < 4; i++) {
                            int hex = c >>> 12;
                            buffer.append((char) (hex > 9 ? hex + 'a' - 10 : hex + '0'));
                            c <<= 4;
                        }
                        break;
                    }
                    buffer.append(c);
            }
        }
        if (htmlMode) {
            buffer.append("</span>&quot;");
        } else if (quoted) {
            buffer.append('"');
        }
    }

    void escapeCharacter(char c) {
        buffer.append('\\').append(c);
    }

    void singleSpace() {
        if (prettyPrint) {
            if (htmlMode) {
                buffer.append("&nbsp;");
            } else {
                buffer.append(' ');
            }
        }
    }

    void printProperty(String name) throws IOException {
        spaceOut();
        printSimpleValue(new JSONValue(JSONTypes.STRING, name), true);
        buffer.append(':');
        singleSpace();
    }

    void spaceOut() {
        for (int i = 0; i < indent; i++) {
            singleSpace();
        }
    }

    /**
     * Serialize current object writer to a Java <code>String</code>.
     * @param outputFormat Any JSONOutputFormats
     * @return JSON string data
     * @throws IOException
     */
    @SuppressWarnings("unchecked")
    public String serializeToString(JSONOutputFormats outputFormat) throws IOException {
        buffer = new StringBuilder();
        indentFactor = outputFormat == JSONOutputFormats.PRETTY_HTML ? 
                                                          htmlIndent : STANDARD_INDENT;
        prettyPrint = outputFormat.pretty;
        javaScriptMode = outputFormat.javascript;
        htmlMode = outputFormat.html;
        canonicalized = outputFormat.canonicalized;
        if (root.properties.containsKey(null)) {
            printArray((ArrayList<JSONValue>) root.properties.get(null).value);
        } else {
            printObject(root);
        }
        if (!javaScriptMode) {
            newLine();
        }
        return buffer.toString();
    }

    /**
     * Serialize current object writer to a Java <code>byte[]</code>.
     * @param outputFormat Any JSONOutputFormats
     * @return JSON UTF-8 data
     * @throws IOException
     */
    public byte[] serializeToBytes(JSONOutputFormats outputFormat) throws IOException {
        return UTF8.encode(serializeToString(outputFormat));
    }

    /**
     * Pretty print JSON of current object writer. 
     */
    @Override
    public String toString() {
        try {
            return serializeToString(JSONOutputFormats.PRETTY_PRINT);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
