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
    static final byte MT_UNSIGNED      = (byte) 0x00;
    static final byte MT_NEGATIVE      = (byte) 0x20;
    static final byte MT_BYTE_STRING   = (byte) 0x40;
    static final byte MT_TEXT_STRING   = (byte) 0x60;
    static final byte MT_ARRAY         = (byte) 0x80;
    static final byte MT_MAP           = (byte) 0xa0;
    static final byte MT_BIG_UNSIGNED  = (byte) 0xc2;
    static final byte MT_BIG_SIGNED    = (byte) 0xc3;
    static final byte MT_FALSE         = (byte) 0xf4;
    static final byte MT_TRUE          = (byte) 0xf5;
    static final byte MT_NULL          = (byte) 0xf6;
    static final byte MT_FLOAT16       = (byte) 0xf9;
    static final byte MT_FLOAT32       = (byte) 0xfa;
    static final byte MT_FLOAT64       = (byte) 0xfb;

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

    static void unsupportedTag(byte tag) throws IOException {
        bad(String.format("Unsupported tag: %2x", tag & 0xff));
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
     * Get <code>double</code> value.
     * <p>
     * This method requires that the object is a
     * {@link CBORDouble}, otherwise an exception will be thrown.
     * </p>
     * 
     * @return Double
     * @throws IOException
     */
    public double getDouble() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.DOUBLE);
        return ((CBORDouble) this).value;
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
        
        private byte readByte() throws IOException {
            int i = input.read();
            if (i < 0) {
                eofError();
            }
            return (byte)i;
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

        private long getLongFromBytes(int length) throws IOException {
            long value = 0;
            while (--length >= 0) {
                value <<= 8;
                value += readByte() & 0xffl;
            }
            return value;
        }

        private CBORDouble doubleWithCheck(byte tag, long bitFormat, long rawDouble)
                throws IOException {
            CBORDouble value = new CBORDouble(Double.longBitsToDouble(rawDouble));
            if (value.tag != tag || value.bitFormat != bitFormat) {
                bad(String.format(
                        "Non-deterministic encoding of floating point value, tag:  %2x", tag & 0xff));
            }
            return value;
        }

        private CBORObject getObject() throws IOException {
            byte tag = readByte();

            // Begin with the types uniquely defined by the initial byte
            switch (tag) {
                case MT_BIG_SIGNED:
                case MT_BIG_UNSIGNED:
                    byte[] byteArray = getObject().getByteString();
                    if (byteArray.length == 0) {
                        byteArray = ZERO_BYTE;  // Zero length byte string => n == 0
                    } else if (byteArray[0] == 0) {
                        bad("Non-deterministic encoding: leading zero byte");
                    }
                    BigInteger bigInteger = 
                        (tag == MT_BIG_SIGNED) ?
                            new BigInteger(-1, byteArray).subtract(BigInteger.ONE)
                                                       :
                            new BigInteger(1, byteArray);
                    if (CBORBigInteger.fitsAnInteger(bigInteger)) {
                        bad("Non-deterministic encoding: bignum fits integer");
                    }
                    return new CBORBigInteger(bigInteger);

                case MT_FLOAT16:
                    long rawDouble;
                    long float16 = getLongFromBytes(2);
                    if (float16 == FLOAT16_POS_ZERO) {
                        rawDouble = FLOAT64_POS_ZERO;
                    } else if (float16 == FLOAT16_NEG_ZERO) {
                        rawDouble = FLOAT64_NEG_ZERO;
                    } else if ((float16 & FLOAT16_POS_INFINITY) == FLOAT16_POS_INFINITY) {
                        // Special "number"
                        if (float16 == FLOAT16_POS_INFINITY) {
                            rawDouble = FLOAT64_POS_INFINITY;
                        } else if (float16 == FLOAT16_NEG_INFINITY) {
                            rawDouble = FLOAT64_NEG_INFINITY;
                        } else {
                            // Non-deterministic representations of NaN will be flagged later
                            rawDouble = FLOAT64_NOT_A_NUMBER;
                        }
                    } else {
                        long exp16 = (float16 >>> FLOAT16_FRACTION_SIZE) &
                                       ((1l << FLOAT16_EXPONENT_SIZE) - 1);
                        long frac16 = (float16 << (FLOAT64_FRACTION_SIZE - FLOAT16_FRACTION_SIZE));
                        if (exp16 == 0) {
                            // Unnormalized float16 - In float64 that must translate to normalized 
                            exp16++;
                            do {
                                exp16--;
                                frac16 <<= 1;
                                // Continue until the implicit "1" is in place
                            } while ((frac16 & (1l << FLOAT64_FRACTION_SIZE)) == 0);
                        }
                        rawDouble = 
                        // Sign bit
                        ((float16 & 0x8000l) << 48) +
                        // Exponent.  Put it in front of the fraction
                        ((exp16 + (FLOAT64_EXPONENT_BIAS - FLOAT16_EXPONENT_BIAS)) 
                           << FLOAT64_FRACTION_SIZE) +
                        // Fraction.  Remove everything above
                        (frac16 & ((1l << FLOAT64_FRACTION_SIZE) - 1));
                    }
                    return doubleWithCheck(tag, float16, rawDouble);

                case MT_FLOAT32:
                    long float32 = getLongFromBytes(4);
                    return doubleWithCheck(tag, 
                                           float32,
                                           Double.doubleToLongBits(Float.intBitsToFloat((int)float32)));
 
                case MT_FLOAT64:
                    long float64 = getLongFromBytes(8);
                    return doubleWithCheck(tag, float64, float64);

                case MT_NULL:
                    return new CBORNull();
                    
                case MT_TRUE:
                case MT_FALSE:
                    return new CBORBoolean(tag == MT_TRUE);
                    
                default:
            }

            // Then decode the types blending length data in the initial byte as well
            long n = tag & 0x1fl;
            byte majorType = (byte)(tag & 0xe0);
            if (n > 27) {
                unsupportedTag(tag);
            }
            if (n > 23) {
                int q = 1 << (n - 24);
                long mask = 0xffffffffl << (q / 2) * 8;
                n = 0;
                while (--q >= 0) {
                    n <<= 8;
                    n |= readByte() & 0xffl;
                }
                if ((n & mask) == 0 || (n > 0 && n < 24)) {
                    bad("Non-deterministic encoding of N");
                }
            }
            switch (majorType) {
                case MT_UNSIGNED:
                    return new CBORInteger(n, true);
    
                case MT_NEGATIVE:
                    return new CBORInteger(n + 1, false);
    
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
