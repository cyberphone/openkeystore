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

import java.security.cert.X509Certificate;

import java.util.EnumSet;
import java.util.GregorianCalendar;
import java.util.ArrayList;

import org.webpki.crypto.CertificateUtil;

import org.webpki.util.Base64URL;
import org.webpki.util.ISODateTime;
import org.webpki.util.UTF8;

/**
 * Writes JSON arrays.<p>
 * Data types are dealt with as in {@link JSONObjectWriter}.</p>
 * @see JSONObjectWriter#setArray(String)
 * @see #setArray()
 * @see #setArray(JSONArrayWriter)
 * @see #JSONArrayWriter()
 */
public class JSONArrayWriter {

    ArrayList<JSONValue> array;

    /**
     * For creating a JSON array.<p>
     * Note that this constructor can be used for creating a JSON structure where the
     * outermost part in an array as well as for array sub-objects.</p>
     * @see JSONObjectReader#getJSONArrayReader()
     * @see JSONObjectWriter#setArray(String, JSONArrayWriter)
     * @see #setArray(JSONArrayWriter)
     */
    public JSONArrayWriter() {
        array = new ArrayList<>();
    }

    public JSONArrayWriter(JSONArrayReader reader) {
        array = reader.array;
    }

    JSONArrayWriter add(JSONTypes type, Object value)  {
        array.add(new JSONValue(type, value));
        return this;
    }

    public JSONArrayWriter setString(String value)  {
        return add(JSONTypes.STRING, value);
    }

    public JSONArrayWriter setInt(int value)  {
        return setInt53(value);
    }

    public JSONArrayWriter setInt53(long value)  {
        return add(JSONTypes.NUMBER, JSONObjectWriter.serializeLong(value));
    }

    public JSONArrayWriter setLong(long value)  {
        return setBigInteger(BigInteger.valueOf(value));
    }

    public JSONArrayWriter setMoney(BigDecimal value)  {
        return setString(JSONObjectWriter.moneyToString(value, null));
    }

    public JSONArrayWriter setMoney(BigDecimal value, Integer decimals)  {
        return setString(JSONObjectWriter.moneyToString(value, decimals));
    }

    public JSONArrayWriter setBigDecimal(BigDecimal value)  {
        return setString(JSONObjectWriter.bigDecimalToString(value));
    }

    public JSONArrayWriter setBigInteger(BigInteger value)  {
        return setString(value.toString());
    }

    public JSONArrayWriter setDouble(double value)  {
        return add(JSONTypes.NUMBER, NumberToJSON.serializeNumber(value));
    }

    public JSONArrayWriter setBoolean(boolean value)  {
        return add(JSONTypes.BOOLEAN, Boolean.toString(value));
    }

    public JSONArrayWriter setNULL()  {
        return add(JSONTypes.NULL, "null");
    }

    public JSONArrayWriter setDateTime(GregorianCalendar dateTime, EnumSet<ISODateTime.DatePatterns> format)  {
        return setString(ISODateTime.encode(dateTime, format));
    }

    public JSONArrayWriter setBinary(byte[] value)  {
        return setString(Base64URL.encode(value));
    }

    JSONObjectWriter createWriteable()  {
        JSONObject dummy = new JSONObject();
        dummy.properties.put(null, new JSONValue(JSONTypes.ARRAY, array));
        return new JSONObjectWriter(dummy);
        
    }
    public JSONArrayWriter setSignature (JSONSigner signer) {
        JSONObjectWriter signatureObject = setObject();
        JSONObjectWriter.coreSign(signer, 
                                  signatureObject,
                                  signatureObject,
                                  createWriteable());
        return this;
    }

    static public JSONArrayWriter createCoreCertificatePath(X509Certificate[] certificatePath) {
        JSONArrayWriter arrayWriter = new JSONArrayWriter();
        for (X509Certificate certificate : CertificateUtil.checkCertificatePath(certificatePath)) {
             arrayWriter.setString(Base64URL.encode(
                     CertificateUtil.getBlobFromCertificate(certificate)));
        }
        return arrayWriter;
    }

    /**
     * Create nested array.<p>
     * This method creates a new array writer at the current position.</p>
     * @return Array writer
     * @
     */
    public JSONArrayWriter setArray()  {
        JSONArrayWriter writer = new JSONArrayWriter();
        add(JSONTypes.ARRAY, writer.array);
        return writer;
    }

    /**
     * Create nested array.<p>
     * This method inserts an existing array writer at the current position.</p>
     * @param writer Instance of array writer
     * @return Array writer
     * @
     */
    public JSONArrayWriter setArray(JSONArrayWriter writer)  {
        add(JSONTypes.ARRAY, writer.array);
        return this;
    }

    public JSONObjectWriter setObject()  {
        JSONObjectWriter writer = new JSONObjectWriter();
        add(JSONTypes.OBJECT, writer.root);
        return writer;
    }

    public JSONArrayWriter setObject(JSONObjectWriter writer)  {
        add(JSONTypes.OBJECT, writer.root);
        return this;
    }

    public String serializeToString(JSONOutputFormats outputFormat)  {
        return createWriteable().serializeToString(outputFormat);
    }

    public byte[] serializeToBytes(JSONOutputFormats outputFormat)  {
        return UTF8.encode(serializeToString(outputFormat));
    }

    @Override
    public String toString() {
        return serializeToString(JSONOutputFormats.PRETTY_PRINT);
    }
}
