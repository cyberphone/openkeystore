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

import org.webpki.util.ArrayUtil;

/**
 * Base class for all CBOR objects.
 * 
 */
public abstract class CBORObject {
    
    CBORObject() {}
    
    // True if object has been read
    private boolean readFlag;

    // Supported CBOR types
    static final int MT_UNSIGNED      = 0x00;
    static final int MT_NEGATIVE      = 0x20;
    static final int MT_BYTE_STRING   = 0x40;
    static final int MT_TEXT_STRING   = 0x60;
    static final int MT_ARRAY         = 0x80;
    static final int MT_MAP           = 0xa0;
    static final int MT_TAG_EXTENSION = 0xc0;
    static final int MT_BIG_UNSIGNED  = 0xc2;
    static final int MT_BIG_SIGNED    = 0xc3;
    static final int MT_FALSE         = 0xf4;
    static final int MT_TRUE          = 0xf5;
    static final int MT_NULL          = 0xf6;
    static final int MT_FLOAT16       = 0xf9;
    static final int MT_FLOAT32       = 0xfa;
    static final int MT_FLOAT64       = 0xfb;

    static final BigInteger MIN_INT  = BigInteger.valueOf(Integer.MIN_VALUE);
    static final BigInteger MAX_INT  = BigInteger.valueOf(Integer.MAX_VALUE);
    
    static final BigInteger MIN_LONG = BigInteger.valueOf(Long.MIN_VALUE);
    static final BigInteger MAX_LONG = BigInteger.valueOf(Long.MAX_VALUE);
    
    static final int FLOAT16_FRACTION_SIZE = 10;
    static final int FLOAT32_FRACTION_SIZE = 23;
    static final int FLOAT64_FRACTION_SIZE = 52;

    static final int FLOAT16_EXPONENT_SIZE = 5;
    static final int FLOAT32_EXPONENT_SIZE = 8;
    static final int FLOAT64_EXPONENT_SIZE = 11;

    static final int FLOAT16_EXPONENT_BIAS = 15;
    static final int FLOAT32_EXPONENT_BIAS = 127;
    static final int FLOAT64_EXPONENT_BIAS = 1023;

    static final long FLOAT16_NOT_A_NUMBER = 0x0000000000007e00l;
    static final long FLOAT16_POS_INFINITY = 0x0000000000007c00l;
    static final long FLOAT16_NEG_INFINITY = 0x000000000000fc00l;
    static final long FLOAT16_POS_ZERO     = 0x0000000000000000l;
    static final long FLOAT16_NEG_ZERO     = 0x0000000000008000l;
     
    static final long FLOAT64_NOT_A_NUMBER = 0x7ff8000000000000l;
    static final long FLOAT64_POS_INFINITY = 0x7ff0000000000000l;
    static final long FLOAT64_NEG_INFINITY = 0xfff0000000000000l;
    static final long FLOAT64_POS_ZERO     = 0x0000000000000000l;
    static final long FLOAT64_NEG_ZERO     = 0x8000000000000000l;

    static final long MASK_LOWER_32        = 0x00000000ffffffffl;
    
    abstract CBORTypes internalGetType();

    /**
     * Returns core CBOR type.
     * 
     * @return The CBOR core type
     */
    public CBORTypes getType() {
        return internalGetType();
    }
 
    abstract byte[] internalEncode() throws IOException;

    /**
     * Encodes CBOR object.
     * 
     * @return Byte data
     * @throws IOException
     */
    public byte[] encode() throws IOException {
        return internalEncode();
    }
    
    abstract void internalToString(DiagnosticNotation outputBuffer);

    static void reportError(String error) throws IOException {
        throw new IOException(error);
    }

    static void unsupportedTag(int tag) throws IOException {
        reportError(String.format("Unsupported tag: %02x", tag));
    }

    void nullCheck(Object object) {
        if (object == null) {
            throw new IllegalArgumentException("Null argument");
        }
    }

    byte[] encodeTagAndValue(int tag, int length, long value) {
        byte[] encoded = new byte[length + 1];
        encoded[0] = (byte)tag;
        while (length > 0) {
            encoded[length--] = (byte)value;
            value >>>= 8;
        }
        return encoded;
    }

    byte[] encodeTagAndN(int majorType, long n) {
        // Note: n is actually an UNSIGNED long
        int modifier = (int) n;
        int length = 0;
        if (n < 0 || n > 23) {
            modifier = 27;
            length = 8;
            while (((MASK_LOWER_32 << ((length / 2) * 8)) & n) == 0) {
                modifier--;
                length >>= 1;
            }
        }
        return encodeTagAndValue(majorType | modifier, length, n);
    }

    void checkTypeAndMarkAsRead(CBORTypes requestedCborType) throws IOException {
        if (internalGetType() != requestedCborType) {
            reportError("Is type: " + internalGetType() + ", requested: " + requestedCborType);
        }
        readFlag = true;
    }
    
    private long getConstrainedInteger(BigInteger min, 
                                       BigInteger max, 
                                       String dataType) throws IOException {
        BigInteger value = getBigInteger();
        if (value.compareTo(max) > 0 || value.compareTo(min) < 0) {
            reportError("Value out of range for '" + dataType + "' (" + value.toString() + ")");
        }
        return value.longValue();
    }
    
    /**
     * Returns {@link BigInteger} value.
     * <p>
     * This method requires that the object is a
     * {@link CBORInteger}, otherwise an exception will be thrown.
     * </p>
     * <p>
     * Note that due to the deterministic serialization mode, this method
     * is independent of the underlying CBOR integer type.
     * </p>
     * 
     * @return BigInteger
     * @throws IOException
     */
    public BigInteger getBigInteger() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.INTEGER);
        return ((CBORInteger) this).value;
    }

    /**
     * Returns <code>long</code> value.
      * <p>
     * This method requires that the object is a
     * {@link CBORInteger} and fits a Java (<i>signed</i>) long, 
     * otherwise an exception will be thrown.
     * </p>
     * Also see {@link #getBigInteger()}.
     * 
     * @return Long
     * @throws IOException
     */
    public long getLong() throws IOException {
        return getConstrainedInteger(MIN_LONG, MAX_LONG, "long");
    }

    /**
     * Returns <i>unsigned</i> <code>long</code> value.
      * <p>
     * This method requires that the object is a positive
     * {@link CBORInteger} and fits a Java long (sign bit is used as well),
     * otherwise an exception will be thrown.
     * </p>
     * 
     * @return Long
     * @throws IOException
     */
    public long getUnsignedLong() throws IOException {
        return getConstrainedInteger(BigInteger.ZERO, CBORInteger.MAX_INT64, "unsigned long");
    }

    /**
     * Returns <code>integer</code> value.
     * <p>
     * This method requires that the object is a
     * {@link CBORInteger} and fits a Java (<i>signed</i>) int, 
     * otherwise an exception will be thrown.
     * </p>
     * Also see {@link #getBigInteger()}.
     * 
     * @return Integer
     * @throws IOException
     */
    public int getInt() throws IOException {
        return (int) getConstrainedInteger(MIN_INT, MAX_INT, "int");
    }

    /**
     * Returns <code>floating point</code> value.
     * <p>
     * This method requires that the object is a
     * {@link CBORFloatingPoint}, otherwise an exception will be thrown.
     * </p>
     * 
     * @return Double
     * @throws IOException
     */
    public double getFloatingPoint() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.FLOATING_POINT);
        return ((CBORFloatingPoint) this).value;
    }
 
    /**
     * Returns <code>boolean</code> value.
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
     * Checks for <code>null</code>.
     * <p>
     * If the object is a {@link CBORNull} the call will return
     * <code>true</code>, else it will return <code>false</code>.
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
     * Returns <code>text string</code> value.
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
     * Returns <code>byte string</code> value.
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
     * Returns <code>map</code> object.
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
     * Returns <code>array</code> object.
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
     * Returns tagged object.
     * <p>
     * This method requires that the object is a
     * {@link CBORTaggedObject}, otherwise an exception will be thrown.
     * </p>
     * <p>
     * Note that the <code>big number</code> type is dealt with
     * as a specific primitive, in spite of being a tagged object.
     * </p>
     * @param tagNumber Expected tag number
     * 
     * @return CBOR object
     * @throws IOException
     */
    public CBORObject getTaggedObject(long tagNumber) throws IOException {
        long actualTagNumber = getTagNumber();
        if (actualTagNumber != tagNumber) {
            reportError("Tag number mismatch, requested=" +
                        Long.toUnsignedString(tagNumber) +
                        ", actual=" +
                        Long.toUnsignedString(actualTagNumber));
        }
        return ((CBORTaggedObject) this).object;
    }

    /**
     * Returns tag number.
     * <p>
     * This method requires that the object is a
     * {@link CBORTaggedObject}, otherwise an exception will be thrown.
     * </p>
     * 
     * @return Tag number
     * @throws IOException
     */
    public long getTagNumber() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.TAGGED_OBJECT);
        return ((CBORTaggedObject) this).tagNumber;
    }

    /**
     * Scans object.
     * <p>
     * This method sets the status of this object as well as to possible
     * child objects to &quot;read&quot;.
     * </p>
     * 
     * @see #checkForUnread()
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
        
            case TAGGED_OBJECT:
                scan(((CBORTaggedObject) this).object);
                break;

            default:
        }
        currentObject.readFlag = true;
    }
    
    static class CBORDecoder {

         // The purpose of using a buffer to protect against
         // allocating huge amounts of memory due to malformed
         // CBOR data. That is, even if you verified that the CBOR
         // input data is < 100kbytes, individual objects could ask
         // for megabytes.
        static final int BUFFER_SIZE = 10000;

        private static final byte[] ZERO_BYTE = {0};

        private ByteArrayInputStream input;
        private boolean checkKeySortingOrder;
         
        private CBORDecoder(byte[] encodedCborData, boolean ignoreKeySortingOrder) {
            input = new ByteArrayInputStream(encodedCborData);
            this.checkKeySortingOrder = !ignoreKeySortingOrder;
        }
        
        private void eofError() throws IOException {
            reportError("Malformed CBOR, trying to read past EOF");
        }
        
        private int readByte() throws IOException {
            int i = input.read();
            if (i < 0) {
                eofError();
            }
            return i;
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

        private long getLongFromBytes(int length) throws IOException {
            long value = 0;
            while (--length >= 0) {
                value <<= 8;
                value += readByte();
            }
            return value;
        }

        private long checkLength(long length) throws IOException {
            if (length < 0) {
                reportError("Length < 0");
            }
            return length;
        }

        private CBORFloatingPoint checkDoubleConversion(int tag, long bitFormat, long rawDouble)
                throws IOException {
            CBORFloatingPoint value = new CBORFloatingPoint(Double.longBitsToDouble(rawDouble));
            if (value.tag != tag || value.bitFormat != bitFormat) {
                reportError(String.format(
                        "Non-deterministic encoding of floating point value, tag: %2x", tag & 0xff));
            }
            return value;
        }

        private CBORObject getObject() throws IOException {
            int tag = readByte();

            // Begin with CBOR types that are uniquely defined by the tag byte
            switch (tag) {
                case MT_BIG_SIGNED:
                case MT_BIG_UNSIGNED:
                    byte[] byteArray = getObject().getByteString();
                    if (byteArray.length == 0) {
                        byteArray = ZERO_BYTE;  // Zero length byte string => n == 0
                    } else if (byteArray[0] == 0) {
                        reportError("Non-deterministic encoding: leading zero byte");
                    }
                    BigInteger bigInteger = 
                        (tag == MT_BIG_SIGNED) ?
                            new BigInteger(-1, byteArray).subtract(BigInteger.ONE)
                                               :
                            new BigInteger(1, byteArray);
                    if (CBORInteger.fitsAnInteger(bigInteger)) {
                        reportError("Non-deterministic encoding: bignum fits integer");
                    }
                    return new CBORInteger(bigInteger);

                case MT_FLOAT16:
                    long rawDouble;
                    long float16 = getLongFromBytes(2);
                    if ((float16 & ~FLOAT16_NEG_ZERO) == FLOAT16_POS_ZERO) {
                        rawDouble = (float16 == FLOAT16_POS_ZERO) ?
                                                 FLOAT64_POS_ZERO : FLOAT64_NEG_ZERO;
                    } else if ((float16 & FLOAT16_POS_INFINITY) == FLOAT16_POS_INFINITY) {
                        // Special "number"
                        if (float16 == FLOAT16_POS_INFINITY) {
                            rawDouble = FLOAT64_POS_INFINITY;
                        } else {
                            // Non-deterministic representations of NaN will be flagged later
                            rawDouble = (float16 == FLOAT16_NEG_INFINITY) ?
                                                     FLOAT64_NEG_INFINITY : FLOAT64_NOT_A_NUMBER;
                        }
                    } else {
                        // Get the bare (but still biased) float16 exponent
                        long exp16 = (float16 >>> FLOAT16_FRACTION_SIZE) &
                                       ((1l << FLOAT16_EXPONENT_SIZE) - 1);
                        // Relocate the float16 fraction bits to their proper float64 position
                        long frac16 = (float16 << (FLOAT64_FRACTION_SIZE - FLOAT16_FRACTION_SIZE));
                        if (exp16 == 0) {
                            // Subnormal float16 - In float64 that must translate to normalized 
                            exp16++;
                            do {
                                exp16--;
                                frac16 <<= 1;
                                // Continue until the implicit "1" is in the proper position
                            } while ((frac16 & (1l << FLOAT64_FRACTION_SIZE)) == 0);
                        }
                        rawDouble = 
                        // Put possible sign bit in position
                        ((float16 & FLOAT16_NEG_ZERO) << (64 - 16)) +
                        // Exponent.  Set the proper bias and put the result in front of fraction
                        ((exp16 + (FLOAT64_EXPONENT_BIAS - FLOAT16_EXPONENT_BIAS)) 
                           << FLOAT64_FRACTION_SIZE) +
                        // Fraction.  Remove everything above
                        (frac16 & ((1l << FLOAT64_FRACTION_SIZE) - 1));
                    }
                    return checkDoubleConversion(tag, float16, rawDouble);

                case MT_FLOAT32:
                    long float32 = getLongFromBytes(4);
                    return checkDoubleConversion(tag, 
                                                 float32,
                                                 Double.doubleToLongBits(
                                                         Float.intBitsToFloat((int)float32)));
 
                case MT_FLOAT64:
                    long float64 = getLongFromBytes(8);
                    return checkDoubleConversion(tag, float64, float64);

                case MT_NULL:
                    return new CBORNull();
                    
                case MT_TRUE:
                case MT_FALSE:
                    return new CBORBoolean(tag == MT_TRUE);
            }

            // Then decode CBOR types that blend length of data in the tag byte
            long n = tag & 0x1fl;
            if (n > 27) {
                unsupportedTag(tag);
            }
            if (n > 23) {
                // For 1, 2, 4, and 8 byte N
                int q = 1 << (n - 24);
                // 1: 00000000ffffffff
                // 2: 000000ffffffff00
                // 4: 0000ffffffff0000
                // 8: ffffffff00000000
                long mask = MASK_LOWER_32 << (q / 2) * 8;
                n = 0;
                while (--q >= 0) {
                    n <<= 8;
                    n |= readByte();
                }
                // If the upper half (for 2, 4, 8 byte N) of N or a single byte
                // N is zero, a shorter variant should have been used.
                // In addition, a single byte N must be > 23. 
                if ((n & mask) == 0 || (n > 0 && n < 24)) {
                    reportError("Non-deterministic encoding of N");
                }
            }
            // N successfully decoded, now switch on major type (upper three bits)
            switch (tag & 0xe0) {
                case MT_TAG_EXTENSION:
                    return new CBORTaggedObject(n, getObject());

                case MT_UNSIGNED:
                    return new CBORInteger(n, true);
    
                case MT_NEGATIVE:
                    return new CBORInteger(n, false);
    
                case MT_BYTE_STRING:
                    return new CBORByteString(readBytes(checkLength(n)));
    
                case MT_TEXT_STRING:
                    return new CBORTextString(new String(readBytes(checkLength(n)), "utf-8"));
    
                case MT_ARRAY:
                    n = checkLength(n);
                    CBORArray cborArray = new CBORArray();
                    while (--n >= 0) {
                        cborArray.addObject(getObject());
                    }
                    return cborArray;
    
                case MT_MAP:
                    n = checkLength(n);
                    CBORMap cborMap = new CBORMap();
                    while (--n >= 0) {
                        cborMap.setObject(getObject(), getObject());
                        cborMap.parsingMode = checkKeySortingOrder;
                    }
                    cborMap.parsingMode = false;
                    return cborMap;
    
                default:
                    unsupportedTag(tag);
            }
            return null;  // For the compiler only...
        }

        private void checkForUnexpectedInput() throws IOException {
            if (input.read() != -1) {
                reportError("Unexpected data found after CBOR object");
            }
        }
    }

    /**
     * Decodes CBOR data with options.
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
     * Decodes CBOR data.
     * 
     * @param encodedCborData
     * @return CBORObject
     * @throws IOException
     */
    public static CBORObject decode(byte[] encodedCborData) throws IOException {
        return decodeWithOptions(encodedCborData, false, false);
    }

    /**
     * Checks for unread CBOR data.
     * 
     * Checks if all data from the current object including
     * possible child objects have been read
     * and throws an exception if this is not the case.
     * 
     * @see #scan()
     * 
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
        
            case TAGGED_OBJECT:
                CBORTaggedObject cborTaggedObject = (CBORTaggedObject) this;
                cborTaggedObject.object.checkForUnread(cborTaggedObject);
                break;

            default:
        }
        if (!readFlag) {
            reportError((holderObject == null ? "Data" : 
                        holderObject instanceof CBORArray ? "Array element" :
                            holderObject instanceof CBORTaggedObject ?
                            "Tagged object " + Long.toUnsignedString(holderObject.getTagNumber()) : 
                            "Map key " + holderObject.toString()) +                    
                        " of type=" + getClass().getSimpleName() + 
                        " with value=" + toString() + " was never read");
        }
    }

    class DiagnosticNotation {
 
        static final String INDENT = "  ";
        
        private int indentationLevel;
        private StringBuilder outputBuffer;
               
        private DiagnosticNotation() {
            outputBuffer = new StringBuilder();
        }

        void newlineAndIndent() {
            outputBuffer.append('\n');
            for (int i = 0; i < indentationLevel; i++) {
                outputBuffer.append(INDENT);
            }
        }
        
        void beginMap() {
            outputBuffer.append('{');
            indentationLevel++;
        }

        void endMap(boolean notEmpty) {
            indentationLevel--;
            if (notEmpty) {
                newlineAndIndent();
            }
            outputBuffer.append('}');
        }

        DiagnosticNotation append(String text) {
            outputBuffer.append(text);
            return this;
        }

        DiagnosticNotation append(char c) {
            outputBuffer.append(c);
            return this;
        }
        
        String getTextualCbor() {
            return outputBuffer.toString();
        }
    }

    /**
     * Checks CBOR objects for equality.
     */
    @Override
    public boolean equals(Object object) {
        try {
            return ArrayUtil.compare(((CBORObject) object).internalEncode(), internalEncode());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Returns CBOR object as a string in diagnostic notation.
     */
    @Override
    public String toString() {
        DiagnosticNotation outputBuffer = new DiagnosticNotation();
        internalToString(outputBuffer);
        return outputBuffer.getTextualCbor();
    }
}
