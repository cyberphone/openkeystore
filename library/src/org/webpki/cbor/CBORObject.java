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
package org.webpki.cbor;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import java.math.BigInteger;

import java.util.Arrays;

import org.webpki.util.UTF8;

/**
 * Base class for all CBOR objects.
 * <p>
 * In this implementation "object" should be regarded as equivalent to the RFC 8949 "data item".
 * </p>
 */
public abstract class CBORObject implements Cloneable {
    
    CBORTypes cborType;
    
    CBORObject(CBORTypes cborType) {
        this.cborType = cborType;
    }
    
    // True if object has been read
    private boolean readFlag;

    // Supported CBOR types
    static final int MT_UNSIGNED      = 0x00;
    static final int MT_NEGATIVE      = 0x20;
    static final int MT_BYTES         = 0x40;
    static final int MT_STRING        = 0x60;
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

    static final long FLOAT16_NOT_A_NUMBER    = 0x0000000000007e00L;
    static final long FLOAT16_POS_INFINITY    = 0x0000000000007c00L;
    static final long FLOAT16_NEG_INFINITY    = 0x000000000000fc00L;
    static final long FLOAT16_POS_ZERO        = 0x0000000000000000L;
    static final long FLOAT16_NEG_ZERO        = 0x0000000000008000L;
     
    static final long FLOAT64_NOT_A_NUMBER    = 0x7ff8000000000000L;
    static final long FLOAT64_POS_INFINITY    = 0x7ff0000000000000L;
    static final long FLOAT64_NEG_INFINITY    = 0xfff0000000000000L;
    static final long FLOAT64_POS_ZERO        = 0x0000000000000000L;
    static final long FLOAT64_NEG_ZERO        = 0x8000000000000000L;

    static final long MASK_LOWER_32           = 0x00000000ffffffffL;
    
    static final long UINT32_MASK             = 0xffffffff00000000L;
    static final long UINT16_MASK             = 0xffffffffffff0000L;
    static final long UINT8_MASK              = 0xffffffffffffff00L;
    
    static final int  MAX_ERROR_MESSAGE       = 100;
    
    /**
     * Get core CBOR type.
     * 
     * @return CBOR core type
     */
    public CBORTypes getType() {
        return cborType;
    }

    // This solution is simply to get a JavaDoc that is more logical...
    abstract byte[] internalEncode();

    /**
     * Encode CBOR object.
     * <p>
     * Note: this method always return CBOR data using 
     * <a href='package-summary.html#deterministic-encoding'>Deterministic&nbsp;Encoding</a>.
     * </p>
     * 
     * @return CBOR encoded <code>byteArray</code>
     */
    public byte[] encode() {
        return internalEncode();
    }
    
    abstract void internalToString(CborPrinter outputBuffer);

    static void cborError(String error) {
        if (error.length() > MAX_ERROR_MESSAGE) {
            error = error.substring(0, MAX_ERROR_MESSAGE - 3) + " ...";
        }
        throw new CBORException(error);
    }

    static CBORArray checkCOTX(CBORObject taggedObject) {
        CBORArray holder = taggedObject.cborType == CBORTypes.ARRAY ? 
                                            taggedObject.getArray() : null;
        if (holder == null || holder.size() != 2 || holder.get(0).cborType != CBORTypes.STRING) {
            cborError("Invalid COTX object: " + taggedObject.toDiagnosticNotation(false));
        }
        return holder;
    }

    static void unsupportedTag(int tag) {
        cborError(String.format(STDERR_UNSUPPORTED_TAG + "%02x", tag));
    }
    
    static void nullCheck(Object object) {
        if (object == null) {
            throw new IllegalArgumentException(STDERR_ARGUMENT_IS_NULL);
        }
    }

    static byte[] addByteArrays(byte[]a, byte[] b) {
        byte[] result = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    static void integerRangeError(String integerType) {
        cborError(STDERR_INT_RANGE + integerType);
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
            length = 32;
            while (((MASK_LOWER_32 << length) & n) == 0) {
                modifier--;
                length >>= 1;
            }
        }
        return encodeTagAndValue(majorType | modifier, length >> 2, n);
    }

    void checkTypeAndMarkAsRead(CBORTypes requestedCborType) {
        if (cborType != requestedCborType) {
            cborError("Is type: " + cborType + ", requested: " + requestedCborType);
        }
        readFlag = true;
    }

    private CBORInt getCBORInt() {
        checkTypeAndMarkAsRead(CBORTypes.INTEGER);
        return (CBORInt) this;
    }

    /**
     * Get CBOR {@link BigInteger} value.
     * <p>
     * This method requires that the object is a
     * {@link CBORBigInt} or {@link CBORInt},
     * otherwise a {@link CBORException} is thrown.
     * </p>
     * 
     * @return <code>BigInteger</code>
     * @throws CBORException
     */
    public BigInteger getBigInteger() {
        if (cborType == CBORTypes.INTEGER) {
            return getCBORInt().toBigInteger();
        }
        checkTypeAndMarkAsRead(CBORTypes.BIGNUM);
        return ((CBORBigInt) this).value;
    }

    /**
     * Get CBOR <code>integer</code>.
     * <p>
     * This method requires that the object is a
     * {@link CBORInt} and has a value ranging from
     * <code>-0x8000000000000000</code> to 
     * <code>0x7fffffffffffffff</code>.
     * </p>
     * 
     * @return <code>long</code>
     * @throws CBORException
     */
    public long getInt64() {
        CBORInt CBORInt = getCBORInt();
        long value = CBORInt.unsigned ? CBORInt.value : ~CBORInt.value;
        if (CBORInt.unsigned == (value < 0)) {
            integerRangeError("long");
        }
        return value;
    }

    /**
     * Get CBOR <code>integer</code>.
     * <p>
     * This method requires that the object is a
     * {@link CBORInt} and has a value ranging from
     * <code>0</code> to 
     * <code>0xffffffffffffffff</code>.
     * </p>
     * 
     * @return <code>long</code>
     * @throws CBORException
     */
    public long getUint64() {
        CBORInt CBORInt = getCBORInt();
        if (!CBORInt.unsigned) {
            cborError(STDERR_NOT_UNSIGNED);
        }
        return CBORInt.value;
    }

    /**
     * Get CBOR <code>integer</code>.
     * <p>
     * This method requires that the object is a
     * {@link CBORInt} and has a value ranging from
     * <code>-0x80000000</code> to 
     * <code>0x7fffffff</code>.
     * </p>
     * 
     * @return <code>int</code>
     * @throws CBORException
     */
    public int getInt32() {
        long value = getInt64();
        if (value > Integer.MAX_VALUE || value < Integer.MIN_VALUE) {
            integerRangeError("int");
        }
        return (int)value;
    }

    /**
     * Get CBOR <code>integer</code>.
     * <p>
     * This method requires that the object is a
     * {@link CBORInt} and has a value ranging from
     * <code>0</code> to 
     * <code>0xffffffff</code>.
     * </p>
     * 
     * @return <code>long</code>
     * @throws CBORException
     */
    public long getUint32() {
        long value = getUint64();
        if ((value & UINT32_MASK) != 0) {
            integerRangeError("int");
        }
        return value;
    }    

    /**
     * Get CBOR <code>integer</code>.
     * <p>
     * This method requires that the object is a
     * {@link CBORInt} and has a value ranging from
     * <code>-0x8000</code> to 
     * <code>0x7fff</code>.
     * </p>
     * 
     * @return <code>int</code>
     * @throws CBORException
     */
    public int getInt16() {
        long value = getInt64();
        if (value > Short.MAX_VALUE || value < Short.MIN_VALUE) {
            integerRangeError("short");
        }
        return (int)value;
    }

    /**
     * Get CBOR <code>integer</code>.
     * <p>
     * This method requires that the object is a
     * {@link CBORInt} and has a value ranging from
     * <code>0</code> to 
     * <code>0xffff</code>.
     * </p>
     * 
     * @return <code>int</code>
     * @throws CBORException
     */
    public int getUint16() {
        long value = getUint64();
        if ((value & UINT16_MASK) != 0) {
            integerRangeError("short");
        }
        return (int)value;
    }    

    /**
    * Get CBOR <code>integer</code>.
     * <p>
     * This method requires that the object is a
     * {@link CBORInt} and has a value ranging from
     * <code>-0x80</code> to 
     * <code>0x7f</code>.
     * </p>
     * 
     * @return <code>int</code>
     * @throws CBORException
     */
    public int getInt8() {
        long value = getInt64();
        if (value > Byte.MAX_VALUE || value < Byte.MIN_VALUE) {
            integerRangeError("byte");
        }
        return (int)value;
    }

    /**
     * Get CBOR <code>integer</code>.
     * <p>
     * This method requires that the object is a
     * {@link CBORInt} and has a value ranging from
     * <code>0</code> to 
     * <code>0xff</code>.
     * </p>
     * 
     * @return <code>int</code>
     * @throws CBORException
     */
    public int getUint8() {
        long value = getUint64();
        if ((value & UINT8_MASK) != 0) {
            integerRangeError("byte");
        }
        return (int)value;
    }    

    /**
     * Get CBOR <code>floating point</code> value.
     * <p>
     * This method requires that the object is a
     * {@link CBORFloat}, otherwise a {@link CBORException} is thrown.
     * </p>
     * 
     * @return <code>double</code>
     * @throws CBORException
     */
    public double getFloat64() {
        checkTypeAndMarkAsRead(CBORTypes.FLOATING_POINT);
        return ((CBORFloat) this).value;
    }
 
    /**
     * Get CBOR <code>floating point</code> value.
     * <p>
     * This method requires that the object is a
     * {@link CBORFloat} holding a 16 or 32-bit IEEE 754 value, 
     * otherwise a {@link CBORException} is thrown.
     * </p>
     * 
     * @return <code>float</code>
     * @throws CBORException
     */
    public float getFloat32() {
        checkTypeAndMarkAsRead(CBORTypes.FLOATING_POINT);
        CBORFloat floatingPoint = (CBORFloat) this;
        if (floatingPoint.tag == MT_FLOAT64) {
            cborError(STDERR_FLOAT_RANGE);
        }
        return (float)floatingPoint.value;
    }

    /**
     * Get CBOR <code>boolean</code>.
     * <p>
     * This method requires that the object is a
     * {@link CBORBoolean}, otherwise a {@link CBORException} is thrown.
     * </p>
     * 
     * @return <code>boolean</code>
     * @throws CBORException
     */
    public boolean getBoolean() {
        checkTypeAndMarkAsRead(CBORTypes.BOOLEAN);
        return ((CBORBoolean) this).value;
    }

    /**
     * Check for CBOR <code>null</code>.
     * <p>
     * If the object is a {@link CBORNull} the call will return
     * <code>true</code>, else it will return <code>false</code>.
     * </p>
     * <p>
     * Note that the object will only be considered as "read"
     * ({@link #checkForUnread()}) if the object is a {@link CBORNull}.
     * </p>
     * 
     * @return <code>boolean</code>
     */
    public boolean isNull() {
        if (cborType == CBORTypes.NULL) {
            readFlag = true;
            return true;
        }
        return false;
    }
    
    /**
     * Get CBOR <code>text string</code>.
     * <p>
     * This method requires that the object is a 
     * {@link CBORString}, otherwise a {@link CBORException} is thrown.
     * </p>
      * 
     * @return <code>String</code>
     * @throws CBORException
     */
    public String getString() {
        checkTypeAndMarkAsRead(CBORTypes.STRING);
        return ((CBORString) this).textString;
    }

    /**
     * Get CBOR <code>byte string</code>.
     * <p>
     * This method requires that the object is a
     * {@link CBORBytes}, otherwise a {@link CBORException} is thrown.
     * </p>
     * 
     * @return <code>byteArray</code>
     * @throws CBORException
     */
    public byte[] getBytes() {
        checkTypeAndMarkAsRead(CBORTypes.BYTES);
        return ((CBORBytes) this).byteString;
    }

    /**
     * Get CBOR <code>map</code> object.
     * <p>
     * This method requires that the object is a
     * {@link CBORMap}, otherwise a {@link CBORException} is thrown.
     * </p>
     * 
     * @return CBOR <code>map</code> object
     * @throws CBORException
     */
    public CBORMap getMap() {
        checkTypeAndMarkAsRead(CBORTypes.MAP);
        return (CBORMap) this;
    }

    /**
     * Get CBOR <code>array</code> object.
     * <p>
     * This method requires that the object is a
     * {@link CBORArray}, otherwise a {@link CBORException} is thrown.
     * </p>
     * 
     * @return CBOR <code>array</code> object
     * @throws CBORException
     */
    public CBORArray getArray() {
        checkTypeAndMarkAsRead(CBORTypes.ARRAY);
        return (CBORArray) this;
    }
    
    /**
     * Get CBOR <code>tag</code> object.
     * <p>
     * This method requires that the object is a
     * {@link CBORTag}, otherwise a {@link CBORException} is thrown.
     * </p>
     * 
     * @return CBOR <code>tag</code> object
     * @throws CBORException
     */
    public CBORTag getTag() {
        checkTypeAndMarkAsRead(CBORTypes.TAG);
        return (CBORTag) this;
    }

    /**
     * Scan CBOR object and mark it as read.
     * <p>
     * This method sets the status of this object as well as to possible
     * child objects to &quot;read&quot;.
     * </p>
     * Also see {@link #checkForUnread()}.
     * 
     * @return <code>this</code>
     */
    public CBORObject scan() {
        traverse(null, false);
        return this;
    }

    /**
     * Check CBOR object for unread data.
     * <p>
     * Verifies that all objects from the current object including
     * possible child objects have been read
     * (through calling {@link #getBytes()} etc.),
     * and throws a {@link CBORException} if this is not the case.
     * </p>
     * Also see {@link #scan()}.
     * @throws CBORException
     */
    public void checkForUnread() {
        traverse(null, true);
    }

    private void traverse(CBORObject holderObject, boolean check) {
        switch (cborType) {
            case MAP:
                CBORMap cborMap = (CBORMap) this;
                for (CBORMap.Entry entry : cborMap.entries) {
                    entry.value.traverse(entry.key, check);
                }
                break;
        
            case ARRAY:
                CBORArray cborArray = (CBORArray) this;
                for (CBORObject object : cborArray.objects) {
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
                cborError((holderObject == null ? "Data" : 
                            holderObject instanceof CBORArray ? "Array element" :
                                holderObject instanceof CBORTag ?
                                "Tagged object " +
                                Long.toUnsignedString(((CBORTag)holderObject).tagNumber) : 
                                "Map key " + holderObject.toDiagnosticNotation(false) + " with argument") +                    
                            " of type=" + cborType + 
                            " with value=" + toDiagnosticNotation(false) + " was never read");
            }
        } else {
            readFlag = true;
        }
    }

    static class CBORDecoder {

        private InputStream inputStream;
        private boolean sequenceFlag;
        private boolean deterministicMode;
        private boolean atFirstByte = true;
        private int maxLength;
        private int byteCount;
         
        private CBORDecoder(InputStream inputStream,
                            boolean sequenceFlag,
                            boolean acceptNonDeterministic,
                            int maxLength) {
            this.inputStream = inputStream;
            this.sequenceFlag = sequenceFlag;
            this.deterministicMode = !acceptNonDeterministic;
            this.maxLength = maxLength;
            if (maxLength < 1) {
                cborError("Invalid \"maxLength\"");
            }
        }
        
        private void eofError() {
            cborError(STDERR_CBOR_EOF);
        }
        
        private void outOfLimitTest(int increment) {
            if ((byteCount += increment) > maxLength || byteCount < 0) {
                cborError(STDERR_READING_LIMIT);
            }
        }
        
        private int readByte() throws IOException {
            int i = inputStream.read();
            if (i < 0) {
                if (sequenceFlag && atFirstByte) {
                    return 0;
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

        private int checkLength(long n) {
            if (n < 0 || n > Integer.MAX_VALUE) {
                cborError(STDERR_N_RANGE_ERROR + n);
            }
            return (int)n;
        }

        private CBORFloat checkDoubleConversion(int tag, long bitFormat, double value) {
            CBORFloat cborFloat = new CBORFloat(value);
            if ((cborFloat.tag != tag || cborFloat.bitFormat != bitFormat) && deterministicMode) {
                cborError(String.format(STDERR_NON_DETERMINISTIC_FLOAT + "%2x", tag));
            }
            return cborFloat;
        }

        private CBORObject getObject() throws IOException {
            int tag = readByte();

            // Begin with CBOR types that are uniquely defined by the tag byte.
            switch (tag) {
                case MT_BIG_NEGATIVE:
                case MT_BIG_UNSIGNED:
                    byte[] byteArray = getObject().getBytes();
                    if ((byteArray.length <= 8 || byteArray[0] == 0) && deterministicMode) {
                        cborError(STDERR_NON_DETERMINISTIC_BIGNUM);
                    }
                    return new CBORBigInt((tag == MT_BIG_NEGATIVE) ?
                        new BigInteger(-1, byteArray).subtract(BigInteger.ONE)
                                           :
                        new BigInteger(1, byteArray));
 
                case MT_FLOAT16:
                    double float64;
                    long f16Binary = getLongFromBytes(2);

                    // Get the significand
                    long significand = f16Binary & ((1l << FLOAT16_SIGNIFICAND_SIZE) - 1);
                    // Get the exponent.
                    long exponent = f16Binary & FLOAT16_POS_INFINITY;

                    // Begin with the edge cases.
          
                    if (exponent == FLOAT16_POS_INFINITY) {

                        // Special "number"
                        
                        // Non-deterministic representations of NaN will be flagged later.
                        // NaN "signaling" is not supported, "quiet" NaN is all there is.
                        float64 = significand == 0 ? Double.POSITIVE_INFINITY : Double.NaN;
                            
                    } else {

                        // It is a "regular" number.
                     
                        if (exponent > 0) {
                            // Normal representation, add the implicit "1.".
                            significand += (1l << FLOAT16_SIGNIFICAND_SIZE);
                            // -1: Keep fractional point in line with subnormal numbers.
                            significand <<= ((exponent >> FLOAT16_SIGNIFICAND_SIZE) - 1);
                        }
                        // Multiply with: 1 / (2 ^ (Exponent offset + Size of significand - 1)).
                        float64 = (double)significand * 
                            (1.0 / (1l << (FLOAT16_EXPONENT_BIAS + FLOAT16_SIGNIFICAND_SIZE - 1)));
                    }
                    return checkDoubleConversion(tag,
                                                 f16Binary,
                                                 f16Binary >= FLOAT16_NEG_ZERO ? 
                                                                      -float64 : float64);

                case MT_FLOAT32:
                    long f32Bin = getLongFromBytes(4);
                    return checkDoubleConversion(tag, f32Bin, Float.intBitsToFloat((int)f32Bin));
 
                case MT_FLOAT64:
                    long f64Bin = getLongFromBytes(8);
                    return checkDoubleConversion(tag, f64Bin, Double.longBitsToDouble(f64Bin));

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
                    cborError(STDERR_NON_DETERMINISTIC_N);
                }
            }
            // N successfully decoded, now switch on major type (upper three bits).
            switch (tag & 0xe0) {
                case MT_TAG:
                    return new CBORTag(n, getObject());

                case MT_UNSIGNED:
                    return new CBORInt(n, true);
    
                case MT_NEGATIVE:
                    return new CBORInt(n, false);
    
                case MT_BYTES:
                    return new CBORBytes(readBytes(checkLength(n)));
    
                case MT_STRING:
                    return new CBORString(UTF8.decode(readBytes(checkLength(n))));
    
                case MT_ARRAY:
                    CBORArray cborArray = new CBORArray();
                    for (int q = checkLength(n); --q >= 0; ) {
                        cborArray.add(getObject());
                    }
                    return cborArray;
    
                case MT_MAP:
                    CBORMap cborMap = new CBORMap().setSortingMode(deterministicMode);
                    for (int q = checkLength(n); --q >= 0; ) {
                        cborMap.set(getObject(), getObject());
                    }
                    // Programmatically added elements will be sorted (by default). 
                    return cborMap.setSortingMode(false);
    
                default:
                    unsupportedTag(tag);
            }
            return null;  // For the compiler only...
        }
    }

    /**
     * Decode CBOR data with options.
     * <p>
     * Also see {@link CBORSequenceBuilder}.
     * </p>
     * <p>
     * Decoding errors throw {@link CBORException}.
     * </p>
     * 
     * @param inputStream Stream holding CBOR data
     * @param sequenceFlag If <code>true</code> stop reading after decoding a CBOR object
     * (no object returns <code>null</code>).
     * @param nonDeterministic If <code>true</code> disable 
     * <a href='package-summary.html#deterministic-encoding'>Deterministic&nbsp;Encoding</a>
     * checks for number serialization and map <i>sorting</i>.
     * See also {@link CBORMap#setSortingMode(boolean)}.
     * @param maxLength Holds maximum input size in 
     * bytes or <code>null</code> ({@link Integer#MAX_VALUE} is assumed).
     * Since malformed CBOR objects can request arbitrary amounts of memory,
     * it is <i>highly recommended</i> setting <code>maxLength</code> to
     * a value that is adapted to the actual application. 
     * @return <code>CBORObject</code>
     */
    public static CBORObject decode(InputStream inputStream,
                                    boolean sequenceFlag,
                                    boolean nonDeterministic,
                                    Integer maxLength) {
        CBORDecoder cborDecoder = new CBORDecoder(inputStream, 
                                                  sequenceFlag, 
                                                  nonDeterministic,
                                                  maxLength == null ? Integer.MAX_VALUE : maxLength);
        
        try {
            CBORObject cborObject = cborDecoder.getObject();
            if (sequenceFlag) {
                if (cborDecoder.atFirstByte) {
                    return null;
                }
            } else if (inputStream.read() != -1) {
                cborError(STDERR_UNEXPECTED_DATA);
            }
            return cborObject;
        } catch (IOException e) {
            throw new CBORException(e);
        }
    }

    /**
     * Decode CBOR data.
     * <p>
     * This method is identical to:
     * <pre>  decode(new ByteArrayInputStream(cborData),
     *         false, 
     *         false,
     *         cborData.length);
     *</pre>
     * </p>
     * <p>
     * Decoding errors throw {@link CBORException}.
     * </p>
     * 
     * @param cborData CBOR in its binary form
     * @return <code>CBORObject</code>
     */
    public static CBORObject decode(byte[] cborData) {
        return decode(new ByteArrayInputStream(cborData),
                      false, 
                      false,
                      cborData.length);
    }
    
    class CborPrinter {
 
        static final String INDENT = "  ";
        
        private int indentationLevel;
        private StringBuilder outputBuffer;
        private boolean prettyPrint;
               
        private CborPrinter(boolean prettyPrint) {
            outputBuffer = new StringBuilder();
            this.prettyPrint = prettyPrint;
        }

        void newlineAndIndent() {
            if (prettyPrint) {
                outputBuffer.append('\n');
                for (int i = 0; i < indentationLevel; i++) {
                    outputBuffer.append(INDENT);
                }
            }
        }
        
        void beginMap() {
            outputBuffer.append('{');
            indentationLevel++;
        }
        
        void space() {
            if (prettyPrint) {
                outputBuffer.append(' ');
            }
        }

        void endMap(boolean notEmpty) {
            indentationLevel--;
            if (notEmpty) {
                newlineAndIndent();
            }
            outputBuffer.append('}');
        }

        CborPrinter append(String text) {
            outputBuffer.append(text);
            return this;
        }

        CborPrinter append(char c) {
            outputBuffer.append(c);
            return this;
        }
        
        String getTextualCbor() {
            return outputBuffer.toString();
        }
    }

    /**
     * Compare CBOR objects for equality.
     */
    @Override
    public boolean equals(Object object) {
        if (object == null || !(object instanceof CBORObject)) {
            return false;
        }
        return Arrays.equals(((CBORObject) object).encode(), encode());
    }

    /**
     * Calculate hash code of CBOR object.
     */
    @Override
    public int hashCode() {
        byte[] encoded = encode();
        int hash = 0;
        int q = Math.min(encoded.length, 4);
        while (--q >= 0) {
            hash <<= 8;
            hash += encoded[q];
        }
        return hash;
    }

    /**
     * Render CBOR object in
     * <a href='package-summary.html#diagnostic-notation'>Diagnostic Notation</a>.
     * <p>
     * @param prettyPrint If <code>true</code> white space is added to make the 
     * result easier to read.  If <code>false</code> elements are output
     * without additional white space (=single line).
     * </p>
     */
    public String toDiagnosticNotation(boolean prettyPrint) {
        CborPrinter outputBuffer = new CborPrinter(prettyPrint);
        internalToString(outputBuffer);
        return outputBuffer.getTextualCbor();
    }

    /**
     * Render CBOR object in a pretty-printed form.
     * <p>
     * Equivalent to {@link #toDiagnosticNotation(boolean)}
     * with the argument set to <code>true</code>.
     * </p>
     */
    @Override
    public String toString() {
        return toDiagnosticNotation(true);
    }
    
    /**
     * Create deep copy of CBOR object.
     * <p>
     * Note that the copy is assumed to be &quot;unread&quot;
     * ({@link #checkForUnread()}).
     * </p>
     */
    @Override
    public CBORObject clone() {
        return CBORObject.decode(encode());
    }
    
    static final String STDERR_NOT_UNSIGNED =
            "CBOR negative integer does not match \"unsigned\"";

    static final String STDERR_UNSUPPORTED_TAG =
            "Unsupported tag: ";

    static final String STDERR_N_RANGE_ERROR =
            "N out of range: ";

    static final String STDERR_INT_RANGE =
            "CBOR integer does not fit a Java \"";

    static final String STDERR_NON_DETERMINISTIC_BIGNUM =
            "Non-deterministic encoding of bignum";

    static final String STDERR_NON_DETERMINISTIC_FLOAT =
            "Non-deterministic encoding of floating point value, tag: ";

    static final String STDERR_NON_DETERMINISTIC_N =
            "Non-deterministic encoding of N";

    static final String STDERR_CBOR_EOF =
            "Malformed CBOR, trying to read past EOF";
    
    static final String STDERR_UNEXPECTED_DATA =
            "Unexpected data found after CBOR object";
    
    static final String STDERR_READING_LIMIT =
            "Reading past input limit";
    
    static final String STDERR_ARGUMENT_IS_NULL =
            "Argument \"null\" is not permitted";

    static final String STDERR_FLOAT_RANGE =
            "Value out of range for\"float\"";

}
