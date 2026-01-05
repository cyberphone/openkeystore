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
 * For fine-grained control of programmatically created integers,
 * the following methods are provided as an <i>alternative</i> to the constructor:
 * {@link #createInt8(int)},
 * {@link #createUint8(int)},
 * {@link #createInt16(int)},
 * {@link #createUint16(int)},
 * {@link #createInt32(long)},
 * {@link #createUint32(long)}, and
 * {@link #createInt53(long)}.
 * Note that these methods <i>do not change data</i>; they
 * only verify that data is within expected limits, and if that is the case,
 * finish the operation using the standard constructor.
 * </p>
 */
public class CBORInt extends CBORObject {

    static final BigInteger MAX_INT_MAGNITUDE = new BigInteger("ffffffffffffffff", 16);    

    long value;
    boolean unsigned;
    
    /**
     * Creates a CBOR unsigned or signed <code>int</code> object.
     * <p>
     * If the <code>unsigned</code> flag is <code>true</code>, <code>value</code> is treated
     * as an <i>unsigned</i> long with range <code>0</code> to <code>0xffffffffffffffff</code>.
     * </p>
     * <p>
     * If the <code>unsigned</code> flag is <code>false</code>, <code>value</code> is treated
     * as a standard java (<i>signed</i>) long with range <code>-0x8000000000000000</code> to <code>0x7fffffffffffffff</code>.
     * </p>
     * <p>
     * See also {@link CBORBigInt#CBORBigInt(BigInteger)} and
     * {@link CBORObject#getBigInteger()}.
     * </p>
     * 
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
     * Creates a CBOR <code>int</code> object.
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
     * Creates a CBOR <code>int</code> object.
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
     * Creates a CBOR <code>int</code> object.
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
     * Creates a CBOR <code>int</code> object.
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
     * Creates a CBOR <code>int</code> object.
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
     * Creates a CBOR <code>int</code> object.
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
     * Creates a CBOR <code>int</code> object.
     * <p>
     * This method creates a {@link CBORInt} object,
     * where the value is verified to be within
     * <code>-9007199254740991</code> to 
     * <code>9007199254740991</code>.
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
}
