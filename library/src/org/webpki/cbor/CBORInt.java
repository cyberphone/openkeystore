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

import java.math.BigInteger;

import static org.webpki.cbor.CBORInternal.*;

/**
 * Class for holding CBOR <code>int</code> objects.
 * 
 * <div id='negative-integers' class='webpkicomment' style='margin-top:1em'>
 * Note that {@link CBORInt} does not support negative integers (CBOR major type 1)
 * beyond the normal range for 64-bit signed integers 
 * (<span style='white-space:nowrap'><code>-2<sup>63</sup></code></span>&#x2009;).
 * In the unlikely case there is a need to explicitly deal with such integers,
 * using {@link CBORBigInt} is the supported workaround.
 * </div>
 * <p>
 * For better control of the generation of short integers, see
 * {@link #createInt8(int)},
 * {@link #createUint8(int)},
 * {@link #createInt16(int)},
 * {@link #createUint16(int)},
 * {@link #createInt32(long)},
 * {@link #createUint32(long)}, and
 * {@link #createInt53(long)}.
 * </p>
 */
public class CBORInt extends CBORObject {

    static final BigInteger MAX_INT_MAGNITUDE = new BigInteger("ffffffffffffffff", 16);    
    static final BigInteger MIN_INT_VALUE     = new BigInteger("-10000000000000000", 16);

    long value;
    boolean unsigned;
    
    /**
     * Creates a CBOR unsigned or negative <code>int</code> object.
     * <p>
     * Unsigned integers range from <code>0</code> to 
     * <span style='white-space:nowrap'><code>2<sup>64</sup>-1</code></span>,
     * while valid negative integers range from <code>-1</code> to
     * <span style='white-space:nowrap'><code>-2<sup>63</sup></code></span>.
     * </p>
     * <p>
     * See also {@link CBORBigInt#CBORBigInt(BigInteger)} and
     * {@link CBORObject#getBigInteger()}.
     * </p>
     * @param value long value
     * @param unsigned <code>true</code> if value should be considered as unsigned
     * @throws CBORException
     */
    public CBORInt(long value, boolean unsigned) {
        this.value = value;
        this.unsigned = unsigned;
        if (!unsigned && value >= 0) {
            cborError(STDERR_INT_VALUE_OUT_OF_RANGE, 
                MIN_INT_VALUE.add(BigInteger.valueOf(value)).toString());
        }
    }

    /**
     * Creates a CBOR signed <code>int</code> object.
     * <p>
     * This constructor is equivalent to 
     * {@link CBORInt(long,boolean) <code>CBORInt(value, value >= 0)</code>}.
     * </p>
     * @param value Java (signed) long type
     */
    public CBORInt(long value) {
        this(value, value >= 0);
    }

    static CBORInt rangeCheck(long value, int bits, boolean unsigned) {
        long min;
        long max;
        if (bits == 53) {
            min = -9007199254740991L;
            max = 9007199254740991L;
        } else {
            min = unsigned ? 0 : -(1L << (bits - 1));
            max = (unsigned ? 1L << bits : -min) - 1;
        }
        CBORInt cborInt = new CBORInt(value);
        if (value < min || value > max) {
            cborInt.outOfRangeError((unsigned ? "Uint" : "Int") + bits);
        }
        return cborInt;
    }

    /**
     * Creates a CBOR <code>int</code> object.
     * <p>
     * This method creates a {@link CBORInt} object,
     * where the value is verified to be within
     * <code>-0x80</code> to 
     * <code>0x7f</code>.
     * </p>
     * @param value Integer
     * @return {@link CBORInt} object
     * @throws CBORException If value is out of range
     * @see CBORObject#getInt8()
     */
    public static CBORInt createInt8(int value) {
        return rangeCheck(value, 8, false);
    }

    /**
     * Creates a CBOR <code>int</code> object.
     * <p>
     * This method creates a {@link CBORInt} object,
     * where the value is verified to be within
     * <code>0</code> to 
     * <code>0xff</code>.
     * </p>
     * @param value Integer
     * @return {@link CBORInt} object
     * @throws CBORException If value is out of range
     * @see CBORObject#getUint8()
     */
    public static CBORInt createUint8(int value) {
        return rangeCheck(value, 8, true);
    }

    /**
     * Creates a CBOR <code>int</code> object.
     * <p>
     * This method creates a {@link CBORInt} object,
     * where the value is verified to be within
     * <code>-0x8000</code> to 
     * <code>0x7fff</code>.
     * </p>
     * @param value Integer
     * @return {@link CBORInt} object
     * @throws CBORException If value is out of range
     * @see CBORObject#getInt16()
     */
    public static CBORInt createInt16(int value) {
        return rangeCheck(value, 16, false);
    }

    /**
     * Creates a CBOR <code>int</code> object.
     * <p>
     * This method creates a {@link CBORInt} object,
     * where the value is verified to be within
     * <code>0</code> to 
     * <code>0xffff</code>.
     * </p>
     * @param value Integer
     * @return {@link CBORInt} object
     * @throws CBORException If value is out of range
     * @see CBORObject#getUint16()
     */
    public static CBORInt createUint16(int value) {
        return rangeCheck(value, 16, true);
    }

    /**
     * Creates a CBOR <code>int</code> object.
     * <p>
     * This method creates a {@link CBORInt} object,
     * where the value is verified to be within
     * <code>-0x80000000</code> to 
     * <code>0x7fffffff</code>.
     * </p>
     * @param value Integer
     * @return {@link CBORInt} object
     * @throws CBORException If value is out of range
     * @see CBORObject#getInt32()
     */
    public static CBORInt createInt32(long value) {
        return rangeCheck(value, 32, false);
    }

    /**
     * Creates a CBOR <code>int</code> object.
     * <p>
     * This method creates a {@link CBORInt} object,
     * where the value is verified to be within
     * <code>0</code> to 
     * <code>0xffffffff</code>.
     * </p>
     * @param value Integer
     * @return {@link CBORInt} object
     * @throws CBORException If value is out of range
     * @see CBORObject#getUint32()
     */
    public static CBORInt createUint32(long value) {
        return rangeCheck(value, 32, true);
    }

    /**
     * Creates a CBOR <code>int</code> object.
     * <p>
     * This method creates a {@link CBORInt} object,
     * where the value is verified to be within
     * <code>-9007199254740991</code> to 
     * <code>9007199254740991</code>.
     * </p>
     * @param value Integer
     * @return {@link CBORInt} object
     * @throws CBORException If value is out of range
     * @see CBORObject#getInt53()
     */
    public static CBORInt createInt53(long value) {
        return rangeCheck(value, 53, false);
    }

    @Override
    byte[] internalEncode() {
        return encodeTagAndN(unsigned ? MT_UNSIGNED : MT_NEGATIVE, unsigned ? value : ~value);
    }

    BigInteger toBigInteger() {
        BigInteger bigInteger = BigInteger.valueOf(value);
        return unsigned ? bigInteger.and(MAX_INT_MAGNITUDE) : bigInteger;
    }

    @Override
    void internalToString(CborPrinter cborPrinter) {
        cborPrinter.append(unsigned ? Long.toUnsignedString(value) : Long.toString(value));
    }

    static final String STDERR_INT_VALUE_OUT_OF_RANGE = 
            "Signed \"int\" out of range: %s";

}
