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

import java.math.BigDecimal;
import java.math.BigInteger;

import java.security.cert.X509Certificate;

import java.util.EnumSet;
import java.util.GregorianCalendar;
import java.util.ArrayList;

import org.webpki.crypto.CertificateUtil;

import org.webpki.util.Base64URL;
import org.webpki.util.ISODateTime;

/**
 * Reads JSON array elements.<p>
 * Data types are dealt with as in {@link JSONObjectReader}.</p>
 * @see JSONObjectReader#getArray(String)
 * @see JSONObjectReader#getJSONArrayReader()
 * @see #getArray()
 */
public class JSONArrayReader {

    ArrayList<JSONValue> array;

    int index;

    JSONArrayReader(ArrayList<JSONValue> array) {
        this.array = array;
    }

    public boolean hasMore() {
        return index < array.size();
    }

    public boolean isLastElement() {
        return index == array.size() - 1;
    }

    public int size() {
        return array.size();
    }

    void inRangeCheck() {
        if (!hasMore()) {
            throw new JSONException("Trying to read past of array limit: " + index);
        }
    }

    JSONValue getNextElementCore(JSONTypes expectedType) {
        inRangeCheck();
        JSONValue value = array.get(index++);
        value.readFlag = true;
        JSONTypes.compatibilityTest(expectedType, value);
        return value;
    }

    Object getNextElement(JSONTypes expectedType) {
        return getNextElementCore(expectedType).value;
    }

    public String getString() {
        return (String) getNextElement(JSONTypes.STRING);
    }

    public int getInt() {
        return JSONObjectReader.parseInt(getNextElementCore(JSONTypes.NUMBER));
    }

    public long getInt53() {
        return JSONObjectReader.parseLong(getNextElementCore(JSONTypes.NUMBER));
    }

    public long getLong() {
        return JSONObjectReader.convertBigIntegerToLong(getBigInteger());
    }

    public double getDouble() {
        return Double.valueOf((String) getNextElement(JSONTypes.NUMBER));
    }

    public BigInteger getBigInteger() {
        return JSONObjectReader.parseBigInteger(getString());
    }

    public BigDecimal getMoney() {
        return JSONObjectReader.parseMoney(getString(), null);
    }

    public BigDecimal getMoney(Integer decimals) {
        return JSONObjectReader.parseMoney(getString(), decimals);
    }

    public BigDecimal getBigDecimal() {
        return JSONObjectReader.parseBigDecimal(getString());
    }

    public GregorianCalendar getDateTime(EnumSet<ISODateTime.DatePatterns> constraints) {
        return ISODateTime.decode(getString(), constraints);
    }

    public byte[] getBinary() {
        return Base64URL.decode(getString());
    }

    public boolean getBoolean() {
        return Boolean.valueOf((String) getNextElement(JSONTypes.BOOLEAN));
    }

    public boolean getIfNULL() {
        if (getElementType() == JSONTypes.NULL) {
            scanAway();
            return true;
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    public JSONArrayReader getArray() {
        return new JSONArrayReader((ArrayList<JSONValue>) getNextElement(JSONTypes.ARRAY));
    }

    public JSONTypes getElementType() {
        inRangeCheck();
        return array.get(index).type;
    }

    public JSONObjectReader getObject() {
        return new JSONObjectReader((JSONObject) getNextElement(JSONTypes.OBJECT));
    }

    public void scanAway() {
        getNextElement(getElementType());
    }

    public ArrayList<byte[]> getBinaryArray() {
        ArrayList<byte[]> blobs = new ArrayList<>();
        do {
            blobs.add(getBinary());
        } while (hasMore());
        return blobs;
    }

    public X509Certificate[] getCertificatePath() {
        ArrayList<byte[]> blobs = new ArrayList<>();
        do {
            blobs.add(Base64URL.decode(getString()));
        } while (hasMore());
        return CertificateUtil.makeCertificatePath(blobs);
    }

    public JSONSignatureDecoder getSignature(JSONCryptoHelper.Options options) {
        options.initializeOperation(false);
        JSONObject dummy = new JSONObject();
        dummy.properties.put(null, new JSONValue(JSONTypes.ARRAY, array));
        int save = index;
        index = array.size() - 1;
        JSONObjectReader signature = getObject();
        index = save;
        return new JSONSignatureDecoder(new JSONObjectReader(dummy), 
                                        signature,
                                        signature, 
                                        options);
    }
}
