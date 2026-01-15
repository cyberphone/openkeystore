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

import java.io.IOException;
import java.io.OutputStream;

import java.math.BigInteger;

import java.util.Arrays;

import static org.webpki.cbor.CBORInternal.*;

/**
 * Class for holding CBOR integer objects.
 * <p>
 * For fine-grained control of programmatically created integers,
 * the following methods are provided as an <i>alternative</i> to the constructor:
 * {@link #createInt8(int)},
 * {@link #createUint8(int)},
 * {@link #createInt16(int)},
 * {@link #createUint16(int)},
 * {@link #createInt32(long)},
 * {@link #createUint32(long)},
 * {@link #createInt53(long)},
 * {@link #createInt128(BigInteger)}, and
 * {@link #createUint128(BigInteger)}.
 * Note that these methods <i>do not change data</i>; they
 * only verify that data is within expected limits, and if that is the case,
 * finish the operation using one of the standard constructors.
 * </p>
 */
public class CBORInt extends CBORObject {

    static final BigInteger MAX_INT_MAGNITUDE = new BigInteger("ffffffffffffffff", 16);
    static final BigInteger MIN_INT_NEGATIVE  = new BigInteger("-8000000000000000", 16);

    // "int"
    long value;

    // "bigint"
    BigInteger bigValue;

    // "int/bigint"
    boolean unsigned;

    /**
     * Creates a CBOR <code>integer</code> object.
     * <p>
     * Constructor supporting integers of any size.
     * </p>
     * <p>
     * Note that using this constructor or one of the other constrctors
     * do not affect CBOR encoding; it is only about accommodating integers
     * of different size.
     * </p>
     * 
     * @see CBORObject#getBigInteger()
     * @param value Big integer value
     */
    public CBORInt(BigInteger value) {
        // Maintain a Java-optimized solution using as little BigInteger as possible.
        this.unsigned = value.signum() >= 0;
        if (value.compareTo(MIN_INT_NEGATIVE) >= 0 && value.compareTo(MAX_INT_MAGNITUDE) <= 0) {
            this.value = value.longValue();
        } else {
            bigValue = value;
        }
    }
    
    /**
     * Creates a CBOR <code>int</code> object.
     * <p>
     * If the <code>unsigned</code> flag is <code>true</code>, <code>value</code> is treated
     * as an <i>unsigned</i> long with range <code>0</code> to <code>0xffffffffffffffff</code>.
     * </p>
     * <p>
     * If the <code>unsigned</code> flag is <code>false</code>, <code>value</code> is treated
     * as a standard java (<i>signed</i>) long with range <code>-0x8000000000000000</code> to <code>0x7fffffffffffffff</code>.
     * </p>
     * 
     * @see CBORInt#CBORInt(BigInteger)
     * @param value long value
     * @param unsigned <code>true</code> => unsigned
     */
    public CBORInt(long value, boolean unsigned) {
        this.value = value;
        if (!unsigned && value >= 0) {
            unsigned = true;
        }
        this.unsigned = unsigned;
    }

    /**
     * Creates a CBOR signed <code>int</code> object.
     * <p>
     * This constructor is equivalent to 
     * {@link CBORInt(long,boolean) <code>CBORInt(value, false)</code>}.
     * </p>
     * 
     * @param value Java (<i>signed</i>) long
     */
    public CBORInt(long value) {
        this(value, false);
    }

    static CBORInt rangeCheck(long value, long min, long max) {
        CBORInt cborInt = new CBORInt(value);
        if (value < min || value > max) {
            if (min < 0 && max != MAX_SAFE_JS_INTEGER) {
                max++;
            }
            int bits = 0;
            while (max != 0) {
                max >>>= 1;
                bits++;
            }
            cborInt.outOfRangeError((min == 0 ? "Uint" : "Int") + bits);
        }
        return cborInt;
    }

    /**
     * Creates a CBOR <code>int8</code> object.
     * <p>
     * This method creates a {@link CBORInt} object,
     * where the value is verified to be within
     * <code>-0x80</code> to 
     * <code>0x7f</code>.
     * </p>
     * 
     * @param value Integer
     * @return {@link CBORInt} object
     * @throws CBORException If value is out of range
     * @see CBORObject#getInt8()
     */
    public static CBORInt createInt8(int value) {
        return rangeCheck(value, -0x80L, 0x7fL);
    }

    /**
     * Creates a CBOR <code>uint8</code> object.
     * <p>
     * This method creates a {@link CBORInt} object,
     * where the value is verified to be within
     * <code>0</code> to 
     * <code>0xff</code>.
     * </p>
     * 
     * @param value Integer
     * @return {@link CBORInt} object
     * @throws CBORException If value is out of range
     * @see CBORObject#getUint8()
     */
    public static CBORInt createUint8(int value) {
        return rangeCheck(value, 0L, 0xffL);
    }

    /**
     * Creates a CBOR <code>int16</code> object.
     * <p>
     * This method creates a {@link CBORInt} object,
     * where the value is verified to be within
     * <code>-0x8000</code> to 
     * <code>0x7fff</code>.
     * </p>
     * 
     * @param value Integer
     * @return {@link CBORInt} object
     * @throws CBORException If value is out of range
     * @see CBORObject#getInt16()
     */
    public static CBORInt createInt16(int value) {
        return rangeCheck(value, -0x8000L, 0x7fffL);
    }

    /**
     * Creates a CBOR <code>uint16</code> object.
     * <p>
     * This method creates a {@link CBORInt} object,
     * where the value is verified to be within
     * <code>0</code> to 
     * <code>0xffff</code>.
     * </p>
     * 
     * @param value Integer
     * @return {@link CBORInt} object
     * @throws CBORException If value is out of range
     * @see CBORObject#getUint16()
     */
    public static CBORInt createUint16(int value) {
        return rangeCheck(value, 0L, 0xffffL);
    }

    /**
     * Creates a CBOR <code>int32</code> object.
     * <p>
     * This method creates a {@link CBORInt} object,
     * where the value is verified to be within
     * <code>-0x80000000</code> to 
     * <code>0x7fffffff</code>.
     * </p>
     * 
     * @param value Integer
     * @return {@link CBORInt} object
     * @throws CBORException If value is out of range
     * @see CBORObject#getInt32()
     */
    public static CBORInt createInt32(long value) {
        return rangeCheck(value, -0x80000000L, 0x7fffffffL);
    }

    /**
     * Creates a CBOR <code>uint32</code> object.
     * <p>
     * This method creates a {@link CBORInt} object,
     * where the value is verified to be within
     * <code>0</code> to 
     * <code>0xffffffff</code>.
     * </p>
     * 
     * @param value Integer
     * @return {@link CBORInt} object
     * @throws CBORException If value is out of range
     * @see CBORObject#getUint32()
     */
    public static CBORInt createUint32(long value) {
        return rangeCheck(value, 0L, 0xffffffffL);
    }

    /**
     * Creates a CBOR <code>int53</code> object.
     * <p>
     * This method creates a {@link CBORInt} object,
     * where the value is verified to be within the JavaScript limits
     * <code>Number.MIN_SAFE_INTEGER</code> (<code>-9007199254740991</code>) to
     * <code>Number.MAX_SAFE_INTEGER</code> (<code>9007199254740991</code>).
     * </p>
     * <p>
     * Since 53-bit integers are specific to JavaScript, <code>int53</code> objects
     * should be used with caution in cross-platform scenarios.
     * </p>
     * 
     * @param value Integer
     * @return {@link CBORInt} object
     * @throws CBORException If value is out of range
     * @see CBORObject#getInt53()
     */
    public static CBORInt createInt53(long value) {
        return rangeCheck(value, MIN_SAFE_JS_INTEGER, MAX_SAFE_JS_INTEGER);
    }

    /**
     * Creates a CBOR <code>int128</code> object.
     * <p>
     * This method creates a {@link CBORInt} object,
     * where the value is verified to be within
     * <code>-0x80000000000000000000000000000000</code> to 
     * <code>0x7fffffffffffffffffffffffffffffff</code>.
     * </p>
     * 
     * @param value Integer
     * @return {@link CBORInt} object
     * @throws CBORException If value is out of range
     * @see CBORObject#getInt128()
     */
    public static CBORInt createInt128(BigInteger value) {
        CBORInt cborInt = new CBORInt(value);
        cborInt.getInt128();
        return cborInt;
    }

    /**
     * Creates a CBOR <code>uint128</code> object.
     * <p>
     * This method creates a {@link CBORInt} object,
     * where the value is verified to be within
     * <code>0</code> to 
     * <code>0xffffffffffffffffffffffffffffffff</code>.
     * </p>
     * 
     * @param value Integer
     * @return {@link CBORInt} object
     * @throws CBORException If value is out of range
     * @see CBORObject#getUint128()
     */
    public static CBORInt createUint128(BigInteger value) {
        CBORInt cborInt = new CBORInt(value);
        cborInt.getUint128();
        return cborInt;
    }

    @Override
    void internalEncode(OutputStream outputStream) throws IOException {
        if (bigValue == null) {
            outputStream.write(encodeTagAndN(unsigned ? 
                                          MT_UNSIGNED : MT_NEGATIVE, 
                                             unsigned ? value : ~value));
        } else {
            BigInteger cborAdjusted = unsigned ? bigValue : bigValue.not();
            byte[] encoded = cborAdjusted.toByteArray();
            if (encoded[0] == 0) {
                // Remove leading zero which may be present due to two-complement encoding.
                encoded = Arrays.copyOfRange(encoded, 1, encoded.length);
            }
            if (encoded.length <= 8) {
                // Fits "int" encoding.
                outputStream.write(encodeTagAndN(unsigned ? MT_UNSIGNED : MT_NEGATIVE,
                                                 cborAdjusted.longValue()));
            } else {
                // Needs "bigint" encoding.
                outputStream.write(unsigned ? MT_BIG_UNSIGNED : MT_BIG_NEGATIVE);
                new CBORBytes(encoded).internalEncode(outputStream);
            }
        }
    }

    BigInteger toBigInteger() {
        if (bigValue == null) {
            BigInteger bigInteger = BigInteger.valueOf(value);
            return unsigned ? bigInteger.and(MAX_INT_MAGNITUDE) : bigInteger;
        }
        return bigValue;
    }

    @Override
    void internalToString(CborPrinter cborPrinter) {
        cborPrinter.append(bigValue == null ?
            unsigned ? Long.toUnsignedString(value) : Long.toString(value)
                                              :
            bigValue.toString());
    }
}
