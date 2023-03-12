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
import java.io.IOException;
import java.io.InputStream;

import java.math.BigInteger;

import org.webpki.util.ArrayUtil;

/**
 * Base class for all CBOR objects.
 * <p>
 * In this implementation "object" should be regarded as equivalent to the RFC 8949 "data item".
 * </p>
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
    static final int MT_TAG           = 0xc0;
    static final int MT_BIG_UNSIGNED  = 0xc2;
    static final int MT_BIG_NEGATIVE  = 0xc3;
    static final int MT_FALSE         = 0xf4;
    static final int MT_TRUE          = 0xf5;
    static final int MT_NULL          = 0xf6;
    static final int MT_FLOAT16       = 0xf9;
    static final int MT_FLOAT32       = 0xfa;
    static final int MT_FLOAT64       = 0xfb;

    static final int FLOAT16_SIGNIFICAND_SIZE = 10;
    static final int FLOAT32_SIGNIFICAND_SIZE = 23;
    static final int FLOAT64_SIGNIFICAND_SIZE = 52;

    static final int FLOAT16_EXPONENT_SIZE    = 5;
    static final int FLOAT32_EXPONENT_SIZE    = 8;
    static final int FLOAT64_EXPONENT_SIZE    = 11;

    static final int FLOAT16_EXPONENT_BIAS    = 15;
    static final int FLOAT32_EXPONENT_BIAS    = 127;
    static final int FLOAT64_EXPONENT_BIAS    = 1023;

    static final long FLOAT16_NOT_A_NUMBER    = 0x0000000000007e00l;
    static final long FLOAT16_POS_INFINITY    = 0x0000000000007c00l;
    static final long FLOAT16_NEG_INFINITY    = 0x000000000000fc00l;
    static final long FLOAT16_POS_ZERO        = 0x0000000000000000l;
    static final long FLOAT16_NEG_ZERO        = 0x0000000000008000l;
     
    static final long FLOAT64_NOT_A_NUMBER    = 0x7ff8000000000000l;
    static final long FLOAT64_POS_INFINITY    = 0x7ff0000000000000l;
    static final long FLOAT64_NEG_INFINITY    = 0xfff0000000000000l;
    static final long FLOAT64_POS_ZERO        = 0x0000000000000000l;
    static final long FLOAT64_NEG_ZERO        = 0x8000000000000000l;

    static final long MASK_LOWER_32           = 0x00000000ffffffffl;
    
    /**
     * Returns core CBOR type.
     * 
     * @return The CBOR core type
     */
    public abstract CBORTypes getType();
 
    /**
     * Encodes CBOR object.
     * 
     * @return CBOR bytes
     */
    public abstract byte[] encode();
    
    abstract void internalToString(DiagnosticNotation outputBuffer);

    static void reportError(String error) throws IOException {
        throw new IOException(error);
    }

    static void unsupportedTag(int tag) throws IOException {
        reportError(String.format(STDERR_UNSUPPORTED_TAG + "%02x", tag));
    }

    void nullCheck(Object object) {
        if (object == null) {
            throw new IllegalArgumentException(STDERR_ARGUMENT_IS_NULL);
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
        if (getType() != requestedCborType) {
            reportError("Is type: " + getType() + ", requested: " + requestedCborType);
        }
        readFlag = true;
    }

    private CBORInteger getCborInteger() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.INTEGER);
        return (CBORInteger) this;
    }

    /**
     * Returns {@link BigInteger} value.
     * <p>
     * This method requires that the object is a
     * {@link CBORBigInteger} or {@link CBORInteger},
     * otherwise an exception will be thrown.
     * </p>
     * <p>
     * Note that this method is independent of the underlying CBOR integer type.
     * </p>
     * 
     * @return BigInteger
     * @throws IOException
     */
    public BigInteger getBigInteger() throws IOException {
        if (getType() == CBORTypes.INTEGER) {
            return getCborInteger().toBigInteger();
        }
        checkTypeAndMarkAsRead(CBORTypes.BIG_INTEGER);
        return ((CBORBigInteger) this).value;
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
        CBORInteger cborInteger = getCborInteger();
        long value = cborInteger.unsigned ? cborInteger.value : ~cborInteger.value;
        if (cborInteger.unsigned == (value < 0)) {
            reportError(STDERR_INCOMPATIBLE_LONG);
        }
        return value;
    }

    /**
     * Returns <i>unsigned</i> <code>long</code> value.
      * <p>
     * This method requires that the object is an unsigned
     * {@link CBORInteger} and fits a Java long (sign bit is used as well),
     * otherwise an exception will be thrown.
     * </p>
     * 
     * @return Long
     * @throws IOException
     */
    public long getUnsignedLong() throws IOException {
        CBORInteger cborInteger = getCborInteger();
        if (!cborInteger.unsigned) {
            reportError(STDERR_INCOMPATIBLE_UNSIGNED_LONG);
        }
        return cborInteger.value;
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
        long value = getLong();
        if (value > Integer.MAX_VALUE || value < Integer.MIN_VALUE) {
            reportError(STDERR_INCOMPATIBLE_INT);
        }
        return (int)value;
    }

    /**
     * Returns <code>double</code> value.
     * <p>
     * This method requires that the object is a
     * {@link CBORDouble}, otherwise an exception will be thrown.
     * </p>
     * 
     * @return Double
     * @throws IOException
     */
    public double getDouble() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.FLOATING_POINT);
        return ((CBORDouble) this).value;
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
        checkTypeAndMarkAsRead(getType());
        return getType() == CBORTypes.NULL;
    }
    
    /**
     * Returns <code>text string</code> value.
     * <p>
     * This method requires that the object is a
     * {@link CBORString}, otherwise an exception will be thrown.
     * </p>
     * 
     * @return String
     * @throws IOException
     */
    public String getString() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.TEXT_STRING);
        return ((CBORString) this).textString;
    }

    /**
     * Returns <code>byte string</code> value.
     * <p>
     * This method requires that the object is a
     * {@link CBORBytes}, otherwise an exception will be thrown.
     * </p>
     * 
     * @return Byte array
     * @throws IOException
     */
    public byte[] getBytes() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.BYTE_STRING);
        return ((CBORBytes) this).byteString;
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
     * Returns tag object.
     * <p>
     * This method requires that the object is a
     * {@link CBORTag}, otherwise an exception will be thrown.
     * </p>
     * <p>
     * Note that the <code>big&nbsp;integer</code> type is dealt with
     * as a specific primitive, in spite of being a tagged object.
     * </p>

     * @return Tag object
     * @throws IOException
     */
    public CBORTag getTag() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.TAG);
        return (CBORTag) this;
    }

    /**
     * Scans object node and marks as read.
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
        try {
            traverse(null, false);
            // Never happens so we "neutralize" the declaration
        } catch (IOException e) {} 
        return this;
    }

    /**
     * Checks for unread CBOR data.
     * <p>
     * Verifies that all data from the current object including
     * possible child objects have been read
     * (through calling {@link #getBytes()} etc.),
     * and throws an exception if this is not the case.
     * </p>
     * 
     * @see #scan()
     * 
     * @throws IOException
     */
    public void checkForUnread() throws IOException {
        traverse(null, true);
    }

    private void traverse(CBORObject holderObject, boolean check) throws IOException {
        switch (getType()) {
            case MAP:
                CBORMap cborMap = (CBORMap) this;
                for (CBORMap.Entry entry = cborMap.root; entry != null; entry = entry.next) {
                     entry.value.traverse(entry.key, check);
                }
                break;
        
            case ARRAY:
                CBORArray cborArray = (CBORArray) this;
                for (CBORObject object : cborArray.getObjects()) {
                    object.traverse(cborArray, check);
                }
                break;
        
            case TAG:
                CBORTag cborTag = (CBORTag) this;
                cborTag.object.traverse(cborTag, check);
                break;

            default:
        }
        if (check) {
            if (!readFlag) {
                reportError((holderObject == null ? "Data" : 
                            holderObject instanceof CBORArray ? "Array element" :
                                holderObject instanceof CBORTag ?
                                "Tagged object " +
                                Long.toUnsignedString(((CBORTag)holderObject).tagNumber) : 
                                "Map key " + holderObject.toString()) +                    
                            " of type=" + getClass().getSimpleName() + 
                            " with value=" + toString() + " was never read");
            }
        } else {
            readFlag = true;
        }
    }

    static class CBORDecoder {

        private static final byte[] ZERO_BYTE = {0};

        private InputStream inputStream;
        private boolean sequenceFlag;
        private boolean deterministicMode;
        private boolean constrainedMapKeys;
        private boolean atFirstByte = true;
        private int maxLength;
        private int byteCount;
         
        private CBORDecoder(InputStream inputStream,
                            boolean sequenceFlag,
                            boolean acceptNonDeterministic,
                            boolean constrainedMapKeys,
                            int maxLength) throws IOException {
            this.inputStream = inputStream;
            this.sequenceFlag = sequenceFlag;
            this.deterministicMode = !acceptNonDeterministic;
            this.constrainedMapKeys = constrainedMapKeys;
            this.maxLength = maxLength;
            if (maxLength < 1) {
                reportError("Invalid \"maxLength\"");
            }
        }
        
        private void eofError() throws IOException {
            reportError(STDERR_CBOR_EOF);
        }
        
        private void outOfLimitTest(int increment) throws IOException {
            if ((byteCount += increment) > maxLength || byteCount < 0) {
                reportError(STDERR_READING_LIMIT);
            }
        }
        
        private int readByte() throws IOException {
            int i = inputStream.read();
            if (i < 0) {
                if (sequenceFlag && atFirstByte) {
                    return MT_NULL;
                }
                eofError();
            }
            outOfLimitTest(1);
            atFirstByte = false;
            return i;
        }
        
        private byte[] readBytes(int length) throws IOException {
            outOfLimitTest(length);
            byte[] result = new byte[length];
            int position = 0;
            while (length != 0) {
                int n = inputStream.read(result, position, length);
                if (n == -1) {
                    eofError();
                }
                length -= n;
                position += n;
            }
            return result;
        }

        private long getLongFromBytes(int length) throws IOException {
            long value = 0;
            while (--length >= 0) {
                value <<= 8;
                value += readByte();
            }
            return value;
        }

        private int checkLength(long n) throws IOException {
            if (n < 0 || n > Integer.MAX_VALUE) {
                reportError(STDERR_N_RANGE_ERROR + n);
            }
            return (int)n;
        }

        private CBORDouble checkDoubleConversion(int tag, long bitFormat, long rawDouble)
                throws IOException {
            CBORDouble value = new CBORDouble(Double.longBitsToDouble(rawDouble));
            if ((value.tag != tag || value.bitFormat != bitFormat) && deterministicMode) {
                reportError(String.format(STDERR_NON_DETERMINISTIC_FLOAT + "%2x", tag & 0xff));
            }
            return value;
        }

        private CBORObject getObject() throws IOException {
            int tag = readByte();

            // Begin with CBOR types that are uniquely defined by the tag byte.
            switch (tag) {
                case MT_BIG_NEGATIVE:
                case MT_BIG_UNSIGNED:
                    byte[] byteArray = getObject().getBytes();
                    if (byteArray.length == 0) {
                        byteArray = ZERO_BYTE;  // Zero length byte string => n == 0.
                    } else if (byteArray[0] == 0 && deterministicMode) {
                        reportError(STDERR_LEADING_ZERO);
                    }
                    CBORBigInteger cborBigInteger = new CBORBigInteger(
                        (tag == MT_BIG_NEGATIVE) ?
                            new BigInteger(-1, byteArray).subtract(BigInteger.ONE)
                                               :
                            new BigInteger(1, byteArray));
                    if (cborBigInteger.fitsAnInteger() && deterministicMode) {
                        reportError(STDERR_NON_DETERMINISTIC_INT);
                    }
                    return cborBigInteger;

                case MT_FLOAT16:
                    long float16 = getLongFromBytes(2);
                    long unsignedResult = float16 & ~FLOAT16_NEG_ZERO;

                    // Begin with the edge cases.
                    
                    if ((unsignedResult & FLOAT16_POS_INFINITY) == FLOAT16_POS_INFINITY) {
                        // Special "number"
                        unsignedResult = (unsignedResult == FLOAT16_POS_INFINITY) ?
                            // Non-deterministic representations of NaN will be flagged later.
                            // NaN "signaling" is not supported, "quiet" NaN is all there is.
                            FLOAT64_POS_INFINITY : FLOAT64_NOT_A_NUMBER;

                    } else if (unsignedResult != FLOAT16_POS_ZERO){

                        // It is a "regular" non-zero number.
                    
                        // Get the bare (but still biased) float16 exponent.
                        long exponent = (unsignedResult >>> FLOAT16_SIGNIFICAND_SIZE);
                        // Relocate float16 significand bits to their proper float64 position.
                        long significand = 
                            (unsignedResult << (FLOAT64_SIGNIFICAND_SIZE - FLOAT16_SIGNIFICAND_SIZE));
                        if (exponent == 0) {
                            // Subnormal float16 - In float64 that must translate to normalized.
                            exponent++;
                            do {
                                exponent--;
                                significand <<= 1;
                                // Continue until the implicit "1" is in the proper position.
                            } while ((significand & (1l << FLOAT64_SIGNIFICAND_SIZE)) == 0);
                        }
                        unsignedResult = 
                        // Exponent.  Set the proper bias and put result in front of significand.
                        ((exponent + (FLOAT64_EXPONENT_BIAS - FLOAT16_EXPONENT_BIAS)) 
                            << FLOAT64_SIGNIFICAND_SIZE) +
                        // Significand.  Remove everything above.
                        (significand & ((1l << FLOAT64_SIGNIFICAND_SIZE) - 1));
                    }
                    return checkDoubleConversion(tag,
                                                 float16, 
                                                 unsignedResult +
                                                 // Put sign bit in position.
                                                 ((float16 & FLOAT16_NEG_ZERO) << (64 - 16)));

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

            // Then decode CBOR types that blend length of data in the tag byte.
            long n = tag & 0x1fl;
            if (n > 27) {
                unsupportedTag(tag);
            }
            if (n > 23) {
                // For 1, 2, 4, and 8 byte N.
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
                if (((n & mask) == 0 || (n > 0 && n < 24)) && deterministicMode) {
                    reportError(STDERR_NON_DETERMINISTIC_CODING_OF_N);
                }
            }
            // N successfully decoded, now switch on major type (upper three bits).
            switch (tag & 0xe0) {
                case MT_TAG:
                    CBORObject tagData = getObject();
                    if (n == CBORTag.RESERVED_TAG_COTX) {
                        CBORArray holder = tagData.getArray();
                        if (holder.size() != 2 ||
                            holder.getObject(0).getType() != CBORTypes.TEXT_STRING) {
                            CBORObject.reportError("Tag syntax " +  CBORTag.RESERVED_TAG_COTX +
                                                   "([\"string\", CBOR object]) expected");
                        }
                    }
                    return new CBORTag(n, tagData);

                case MT_UNSIGNED:
                    return new CBORInteger(n, true);
    
                case MT_NEGATIVE:
                    return new CBORInteger(n, false);
    
                case MT_BYTE_STRING:
                    return new CBORBytes(readBytes(checkLength(n)));
    
                case MT_TEXT_STRING:
                    return new CBORString(new String(readBytes(checkLength(n)), "utf-8"));
    
                case MT_ARRAY:
                    CBORArray cborArray = new CBORArray();
                    for (int q = checkLength(n); --q >= 0; ) {
                        cborArray.addObject(getObject());
                    }
                    return cborArray;
    
                case MT_MAP:
                    CBORMap cborMap = new CBORMap();
                    cborMap.deterministicMode = deterministicMode;
                    cborMap.constrainedKeys = constrainedMapKeys;
                    for (int q = checkLength(n); --q >= 0; ) {
                        cborMap.setObject(getObject(), getObject());
                    }
                    // Programmatically added elements sort automatically. 
                    cborMap.deterministicMode = false;
                    return cborMap;
    
                default:
                    unsupportedTag(tag);
            }
            return null;  // For the compiler only...
        }
    }

    /**
     * Decodes CBOR data with options.
     * 
     * @param inputStream Stream holding CBOR data
     * @param sequenceFlag Stop reading after parsing a valid CBOR object
     * (no object returns <code>null</code>)
     * @param nonDeterministic Do not check data for deterministic representation
     * @param constrainedKeys Limit map keys to text string and integer types,
     * including flagging mixing of these types in map
     * @param maxLength Holds maximum input size in 
     * bytes or <code>null</code> ({@link Integer#MAX_VALUE} is assumed)
     * @return CBORObject
     * @throws IOException
     */
    public static CBORObject decode(InputStream inputStream,
                                    boolean sequenceFlag,
                                    boolean nonDeterministic,
                                    boolean constrainedKeys,
                                    Integer maxLength) throws IOException {
        CBORDecoder cborDecoder = new CBORDecoder(inputStream, 
                                                  sequenceFlag, 
                                                  nonDeterministic,
                                                  constrainedKeys,
                                                  maxLength == null ? Integer.MAX_VALUE : maxLength);
        CBORObject cborObject = cborDecoder.getObject();
        if (sequenceFlag) {
            if (cborDecoder.atFirstByte) {
                return null;
            }
        } else if (inputStream.read() != -1) {
            reportError(STDERR_UNEXPECTED_DATA);
        }
        return cborObject;
    }

    /**
     * Decodes CBOR data.
     * <p>
     * This method is identical to:
     * <pre>  decode(new ByteArrayInputStream(encodedCborData),
     *        false, 
     *        false,
     *        false,
     *        encodedCborData.length);
     *</pre>
     * </p>
     * 
     * @param encodedCborData
     * @return CBORObject
     * @throws IOException
     */
    public static CBORObject decode(byte[] encodedCborData) throws IOException {
        return decode(new ByteArrayInputStream(encodedCborData),
                      false, 
                      false,
                      false,
                      encodedCborData.length);
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
            return ArrayUtil.compare(((CBORObject) object).encode(), encode());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Returns CBOR object in pretty-printed diagnostic notation.
     */
    @Override
    public String toString() {
        DiagnosticNotation outputBuffer = new DiagnosticNotation();
        internalToString(outputBuffer);
        return outputBuffer.getTextualCbor();
    }
    
    static final String STDERR_INCOMPATIBLE_UNSIGNED_LONG =
            "CBOR negative integer does not match Java \"unsigned long\"";

    static final String STDERR_UNSUPPORTED_TAG =
            "Unsupported tag: ";

    static final String STDERR_N_RANGE_ERROR =
            "N out of range: ";

    static final String STDERR_INCOMPATIBLE_LONG =
            "CBOR integer does not fit a Java \"long\"";

    static final String STDERR_INCOMPATIBLE_INT =
            "CBOR integer does not fit a Java \"int\"";

    static final String STDERR_NON_DETERMINISTIC_INT =
            "Non-deterministic encoding: big integer fits integer";

    static final String STDERR_NON_DETERMINISTIC_FLOAT =
            "Non-deterministic encoding of floating point value, tag: ";

    static final String STDERR_NON_DETERMINISTIC_CODING_OF_N =
            "Non-deterministic encoding of N";

    static final String STDERR_LEADING_ZERO =
            "Non-deterministic encoding: leading zero byte";
    
    static final String STDERR_CBOR_EOF =
            "Malformed CBOR, trying to read past EOF";
    
    static final String STDERR_UNEXPECTED_DATA =
            "Unexpected data found after CBOR object";
    
    static final String STDERR_READING_LIMIT =
            "Reading past input limit";
    
    static final String STDERR_ARGUMENT_IS_NULL =
            "Argument \"null\" is not permitted";

}
