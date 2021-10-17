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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.math.BigInteger;

import java.util.EnumSet;
import java.util.GregorianCalendar;

import org.webpki.util.ArrayUtil;
import org.webpki.util.ISODateTime;

/**
 * Base class for all CBOR objects.
 * 
 */
public abstract class CBORObject {
    
    CBORObject() {}
    
    // True if object has been read
    private boolean readFlag;

    // Major CBOR types
    static final byte MT_UNSIGNED      = (byte) 0x00;
    static final byte MT_NEGATIVE      = (byte) 0x20;
    static final byte MT_BYTE_STRING   = (byte) 0x40;
    static final byte MT_TEXT_STRING   = (byte) 0x60;
    static final byte MT_ARRAY         = (byte) 0x80;
    static final byte MT_MAP           = (byte) 0xa0;
    static final byte MT_DATE_TIME     = (byte) 0xc0;
    static final byte MT_BIG_UNSIGNED  = (byte) 0xc2;
    static final byte MT_BIG_SIGNED    = (byte) 0xc3;
    static final byte MT_FALSE         = (byte) 0xf4;
    static final byte MT_TRUE          = (byte) 0xf5;
    static final byte MT_NULL          = (byte) 0xf6;

    static final BigInteger MIN_INT  = BigInteger.valueOf(Integer.MIN_VALUE);
    static final BigInteger MAX_INT  = BigInteger.valueOf(Integer.MAX_VALUE);
    
    static final BigInteger MIN_LONG = BigInteger.valueOf(Long.MIN_VALUE);
    static final BigInteger MAX_LONG = BigInteger.valueOf(Long.MAX_VALUE);
    
    abstract CBORTypes internalGetType();

    /**
     * Get core CBOR type.
     * 
     * @return The CBOR core type
     */
    public CBORTypes getType() {
        return internalGetType();
    }
 
    abstract byte[] internalEncode() throws IOException;

    /**
     * Encode CBOR object.
     * 
     * @return Byte data
     * @throws IOException
     */
    public byte[] encode() throws IOException {
        return internalEncode();
    }
    
    abstract void internalToString(PrettyPrinter prettyPrinter);

    static void bad(String error) throws IOException {
        throw new IOException(error);
    }
    
    void nullCheck(Object object) {
        if (object == null) {
            throw new IllegalArgumentException("Null argument");
        }
    }
    
    byte[] getEncodedCore(byte majorType, long value) {
        byte[] encoded;
        if (value < 0 || value > 4294967295L) {
            encoded = new byte[9];
            encoded[0] = 27;
            for (int i = 8; i > 0; i--) {
                encoded[i] = (byte) value;
                value >>>= 8;
            } 
        } else if (value <= 23) {
            encoded = new byte[] {(byte) value};
        } else if (value <= 255) {
            encoded = new byte[] {24, (byte) value};
        } else if (value <= 65535) {
            encoded = new byte[] {25, (byte) (value >> 8),  (byte) value};
        } else {
            encoded = new byte[] {26, (byte) (value >> 24), (byte) (value >> 16), 
                                      (byte) (value >> 8),  (byte) value};
        } 
        encoded[0] |= majorType;
        return encoded;
    }

    void checkTypeAndMarkAsRead(CBORTypes requestedCborType) throws IOException {
        if (internalGetType() != requestedCborType) {
            bad("Is type: " + internalGetType() + ", requested: " + requestedCborType);
        }
        readFlag = true;
    }
    
    private long getConstrainedInteger(BigInteger min, 
                                       BigInteger max, 
                                       String dataType) throws IOException {
        BigInteger value = getIntegerAsBigInteger();
        if (value.compareTo(max) > 0 || value.compareTo(min) < 0) {
            bad("Value out of range for '" + dataType + "' (" + value.toString() + ")");
        }
        return value.longValue();
    }
    
    /**
     * Get CBOR integer as a BigInteger value.
      * <p>
     * This method requires that the object is a
     * {@link CBORInteger}, 
     * otherwise an exception will be thrown.
     * </p>
     * This method supports the full (65-bit) CBOR integer range.
     * 
     * @return BigInteger
     * @throws IOException
     */
    public BigInteger getIntegerAsBigInteger() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.INTEGER);
        return ((CBORInteger) this).returnAsBigInteger();
    }

    /**
     * Get <code>long</code> value.
      * <p>
     * This method requires that the object is a
     * {@link CBORInteger} and fits a Java (<i>signed</i>) long, 
     * otherwise an exception will be thrown.
     * </p>
     * Also see {@link #getIntegerAsBigInteger()}.
     * 
     * @return Long
     * @throws IOException
     */
    public long getLong() throws IOException {
        return getConstrainedInteger(MIN_LONG, MAX_LONG, "long");
    }

    /**
     * Get <i>unsigned</i> <code>long</code> value.
      * <p>
     * This method requires that the object is a positive
     * {@link CBORInteger} and fits a Java long (sign bit is used as well),
     * otherwise an exception will be thrown.
     * </p>
     * Also see {@link #getIntegerAsBigInteger()}.
     * 
     * @return Long
     * @throws IOException
     */
    public long getUnsignedLong() throws IOException {
        return getConstrainedInteger(BigInteger.ZERO, CBORBigInteger.MAX_INT64, "unsigned long");
    }

    /**
     * Get <code>integer</code> value.
     * <p>
     * This method requires that the object is a
     * {@link CBORInteger} and fits a Java (<i>signed</i>) int, 
     * otherwise an exception will be thrown.
     * </p>
     * Also see {@link #getIntegerAsBigInteger()}.
     * 
     * @return Integer
     * @throws IOException
     */
    public int getInt() throws IOException {
        return (int) getConstrainedInteger(MIN_INT, MAX_INT, "int");
    }
    
    /**
     * Get <code>boolean</code> value.
     * <p>
     * This method requires that the object is a
     * {@link CBORBoolean}, otherwise an exception will be thrown.
     * </p>
     * 
     * @return Boolean
     * @throws IOException
     */
    public boolean getBoolean() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.BOOLEAN);
        return ((CBORBoolean) this).value;
    }

    /**
     * Check for <code>null</code>.
     * <p>
     * If the object is a {@link CBORNull} the call will return
     * <code>true</code>, else it will return <code>false></code>.
     * </p>
     * 
     * @return Status
     * @throws IOException
     */
    public boolean isNull() throws IOException {
        checkTypeAndMarkAsRead(internalGetType());
        return internalGetType() == CBORTypes.NULL;
    }
    
    /**
     * Get <code>big number</code> value.
     * <p>
     * This method requires that the object is either a
     * {@link CBORInteger} or a {@link CBORBigInteger}, 
     * otherwise an exception will be thrown.
     * </p>
     * 
     * @return BigInteger
     * @throws IOException
     */
    public BigInteger getBigInteger() throws IOException {
        if (internalGetType() == CBORTypes.INTEGER) {
            return getIntegerAsBigInteger();
        }
        checkTypeAndMarkAsRead(CBORTypes.BIG_INTEGER);
        return ((CBORBigInteger) this).value;
    }

    /**
     * Get <code>text string</code> value.
     * <p>
     * This method requires that the object is a
     * {@link CBORTextString}, otherwise an exception will be thrown.
     * </p>
     * 
     * @return String
     * @throws IOException
     */
    public String getTextString() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.TEXT_STRING);
        return ((CBORTextString) this).textString;
    }

    /**
     * Get <code>date time</code> value.
     * <p>
     * This method requires that the object is a
     * {@link CBORDateTime}, otherwise an exception will be thrown.
     * </p>
     * 
     * @return Date time
     * @throws IOException
     */
    public GregorianCalendar getDateTime() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.DATE_TIME);
        return ((CBORDateTime) this).dateTime;
    }

    /**
     * Get <i>constrained</i> <code>date time</code> value.
     * <p>
     * This method requires that the object is a
     * {@link CBORDateTime}, otherwise an exception will be thrown.
     * </p>
     * 
     * @param constraints Permitted format(s)
     * @return Date time
     * @throws IOException
     */
    public GregorianCalendar getDateTime(EnumSet<ISODateTime.DatePatterns> constraints) 
            throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.DATE_TIME);
        return ((CBORDateTime) this).parseDateTime(constraints);
    }

    /**
     * Get <code>byte string</code> value.
     * <p>
     * This method requires that the object is a
     * {@link CBORByteString}, otherwise an exception will be thrown.
     * </p>
     * 
     * @return Byte array
     * @throws IOException
     */
    public byte[] getByteString() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.BYTE_STRING);
        return ((CBORByteString) this).byteString;
    }

    /**
     * Get <code>map</code> object.
     * <p>
     * This method requires that the object is a
     * {@link CBORMap}, otherwise an exception will be thrown.
     * </p>
     * 
     * @return Map object
     * @throws IOException
     */
    public CBORMap getMap() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.MAP);
        return (CBORMap) this;
    }

    /**
     * Get <code>array</code> object.
     * <p>
     * This method requires that the object is a
     * {@link CBORArray}, otherwise an exception will be thrown.
     * </p>
     * 
     * @return Array object
     * @throws IOException
     */
    public CBORArray getArray() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.ARRAY);
        return (CBORArray) this;
    }
    
    /**
     * Scan object.
     * <p>
     * This method sets the status of this object as well as to possible
     * child objects to &quot;read&quot;.
     * </p>
     * 
     * @return <code>this</code>
     */
    public CBORObject scan() {
        scan(this);
        return this;
    }
    
    private void scan(CBORObject currentObject) {
        switch (currentObject.internalGetType()) {
            case MAP:
                CBORMap cborMap = (CBORMap) currentObject;
                for (CBORObject key : cborMap.keys.keySet()) {
                     scan(cborMap.keys.get(key));
                }
                break;
        
            case ARRAY:
                CBORArray cborArray = (CBORArray) currentObject;
                for (CBORObject object : cborArray.getObjects()) {
                    scan(object);
                }
                break;
        
            default:
        }
        currentObject.readFlag = true;
    }
    
    static class CBORDecoder {

         // The point with BUFFER_SIZE is to protect against
         // allocating huge amounts of memory due to malformed
         // CBOR data. That is, even if you verified that the CBOR
         // input data is < 100kbytes, individual objects could ask
         // for megabytes.
        static final int BUFFER_SIZE = 10000;

        private static final byte[] ZERO_BYTE = {0};
        private ByteArrayInputStream input;
        private boolean checkKeySortingOrder;
         
        private CBORDecoder(byte[] encodedCborData,
                           boolean ignoreKeySortingOrder) {
            input = new ByteArrayInputStream(encodedCborData);
            this.checkKeySortingOrder = !ignoreKeySortingOrder;
        }
        
        private void eofError() throws IOException {
            bad("Malformed CBOR, trying to read past EOF");
        }
        
        private int readByte() throws IOException {
            int i = input.read();
            if (i < 0) {
                eofError();
            }
            return i;
        }
        
        private long checkLength(long length) throws IOException {
            if (length < 0) {
                bad("Length < 0");
            }
            return length;
        }

        private byte[] readBytes(long length) throws IOException {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(BUFFER_SIZE);
            byte[] buffer = new byte[BUFFER_SIZE];
            while (length != 0) {
                int returnedBytes =
                        input.read(buffer, 0, length < BUFFER_SIZE ? (int)length : BUFFER_SIZE);
                if (returnedBytes == -1) {
                    eofError();
                }
                baos.write(buffer, 0, returnedBytes);
                length -= returnedBytes;
            }
            return baos.toByteArray();
        }
        
        private CBORObject getObject() throws IOException {
            int first = readByte();

            // Begin with the types uniquely defined by the initial byte
            switch ((byte)first) {
                case MT_DATE_TIME:
                    return new CBORDateTime(getObject().getTextString()); 
     
                case MT_BIG_SIGNED:
                case MT_BIG_UNSIGNED:
                    byte[] byteArray = getObject().getByteString();
                    if (byteArray.length == 0) {
                        byteArray = ZERO_BYTE;  // Zero length byte string => n == 0
                    } else if (byteArray[0] == 0) {
                        bad("Non-deterministic encoding: leading zero byte");
                    }
                    BigInteger bigInteger = 
                        ((byte)first == MT_BIG_SIGNED) ?
                            new BigInteger(-1, byteArray).subtract(BigInteger.ONE)
                                                       :
                            new BigInteger(1, byteArray);
                    if (CBORBigInteger.fitsAnInteger(bigInteger)) {
                        bad("Non-deterministic encoding: bignum fits integer");
                    }
                    return new CBORBigInteger(bigInteger);
    
                case MT_NULL:
                    return new CBORNull();
                    
                case MT_TRUE:
                case MT_FALSE:
                    return new CBORBoolean((byte)first == MT_TRUE);
                    
                default:
            }

            // Then decode the types blending length data in the initial byte as well
            long length = first & 0x1f;
            byte majorType = (byte)(first & 0xe0);
            if (length > 0x1b) {
                bad("Not implemented: 0x1c-0x1f");
            }
            if (length > 0x17) {
                int q = 1 << (length - 0x18);
                length = 0;
                while (--q >= 0) {
                    length <<= 8;
                    length |= readByte();
                }
                if (length == 0) {
                    bad("Non-deterministic encoding: additional bytes form a zero value");
                }
            }
            switch (majorType) {
                case MT_UNSIGNED:
                    return new CBORInteger(length, true);
    
                case MT_NEGATIVE:
                    return new CBORInteger(length + 1, false);
    
                case MT_BYTE_STRING:
                    return new CBORByteString(readBytes(checkLength(length)));
    
                case MT_TEXT_STRING:
                    return new CBORTextString(new String(readBytes(checkLength(length)), "utf-8"));
    
                case MT_ARRAY:
                    length = checkLength(length);
                    CBORArray cborArray = new CBORArray();
                    while (--length >= 0) {
                        cborArray.addObject(getObject());
                    }
                    return cborArray;
    
                case MT_MAP:
                    length = checkLength(length);
                    CBORMap cborMap = new CBORMap();
                    while (--length >= 0) {
                        cborMap.setObject(getObject(), getObject());
                        cborMap.parsingMode = checkKeySortingOrder;
                    }
                    cborMap.parsingMode = false;
                    return cborMap;
    
                default:
                    bad("Unsupported tag: " + first);
            }
            return null;  // For the compiler only...
        }

        private void checkForUnexpectedInput() throws IOException {
            if (input.read() != -1) {
                bad("Unexpected data found after CBOR object");
            }
        }
    }

    /**
     * Decode CBOR data with options.
     * 
     * @param encodedCborData
     * @param ignoreAdditionalData Stop reading after parsing a valid CBOR object
     * @param ignoreKeySortingOrder Do not enforce any particular sorting order
     * @return CBORObject
     * @throws IOException
     */
    public static CBORObject decodeWithOptions(byte[] encodedCborData,
                                               boolean ignoreAdditionalData,
                                               boolean ignoreKeySortingOrder) throws IOException {
        CBORDecoder cborDecoder = new CBORDecoder(encodedCborData, ignoreKeySortingOrder);
        CBORObject cborObject = cborDecoder.getObject();
        // https://github.com/w3c/webauthn/issues/1614
        if (!ignoreAdditionalData) {
            cborDecoder.checkForUnexpectedInput();
        }
        return cborObject;
    }

    /**
     * Decode CBOR data.
     * 
     * @param encodedCborData
     * @return CBORObject
     * @throws IOException
     */
    public static CBORObject decode(byte[] encodedCborData) throws IOException {
        return decodeWithOptions(encodedCborData, false, false);
    }

    /**
     * Check for unread CBOR data.
     * 
     * Check if all data from the current node and downwards have been read.
     * @throws IOException
     */
    public void checkForUnread() throws IOException {
        checkForUnread(null);
    }

    private void checkForUnread(CBORObject holderObject) throws IOException {
        switch (internalGetType()) {
            case MAP:
                CBORMap cborMap = (CBORMap) this;
                for (CBORObject key : cborMap.keys.keySet()) {
                     cborMap.keys.get(key).checkForUnread(key);
                }
                break;
        
            case ARRAY:
                CBORArray cborArray = (CBORArray) this;
                for (CBORObject object : cborArray.getObjects()) {
                    object.checkForUnread(cborArray);
                }
                break;
        
            default:
        }
        if (!readFlag) {
            bad((holderObject == null ? "Data" : 
                        holderObject instanceof CBORArray ?
                                "Array element" :
                                "Map key " + holderObject.toString()) +                    
                    " of type=" + getClass().getSimpleName() + 
                    " with value=" + toString() + " was never read");
        }
    }

    class PrettyPrinter {
 
        static final String INDENT = "  ";
        
        private int indentationLevel;
        private StringBuilder result;
               
        private PrettyPrinter() {
            result = new StringBuilder();
        }

        PrettyPrinter indent() {
            for (int i = 0; i < indentationLevel; i++) {
                result.append(INDENT);
            }
            return this;
        }
        
        PrettyPrinter beginStructure(String text) {
            appendText(text);
            indentationLevel++;
            return this;
        }

        PrettyPrinter endStructure(String text) {
            indentationLevel--;
            indent();
            appendText(text);
            return this;
        }

        PrettyPrinter appendText(String text) {
            result.append(text);
            return this;
        }
        
        String getTotalText() {
            return result.toString();
        }

        void insertComma() {
            result.insert(result.length() - 1, ',');
        }
    }

    /**
     * Check CBOR objects for equality.
     */
    @Override
    public boolean equals(Object object) {
        try {
            return ArrayUtil.compare(((CBORObject) object).internalEncode(), internalEncode());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Return CBOR object as a string in diagnostic notation.
     */
    @Override
    public String toString() {
        PrettyPrinter prettyPrinter = new PrettyPrinter();
        internalToString(prettyPrinter);
        return prettyPrinter.getTotalText();
    }
}
