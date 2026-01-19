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
import java.io.UncheckedIOException;

import java.math.BigInteger;

import java.time.Instant;
import java.time.ZonedDateTime;

import java.util.Arrays;

import java.util.regex.Pattern;

import static org.webpki.cbor.CBORInternal.*;

/**
 * Base class for all CBOR objects.
 * <p>
 * In this implementation "object" should be regarded as 
 * equivalent to the  
 * CBOR [<a href='https://www.rfc-editor.org/rfc/rfc8949.html' class='webpkilink'>RFC8949</a>]
 * term, "data item".
 * </p>
 */
public abstract class CBORObject implements Cloneable, Comparable<CBORObject> {

    static final BigInteger MIN_INT_128  = new BigInteger("-80000000000000000000000000000000", 16);
    static final BigInteger MAX_INT_128  = new BigInteger("7fffffffffffffffffffffffffffffff", 16);
    static final BigInteger MAX_UINT_128 = new BigInteger("ffffffffffffffffffffffffffffffff", 16);

    // Package level constructor
    CBORObject() {}
    
    // True if object has been read
    private boolean readFlag;

    // True if map key object
    private boolean immutableFlag;

    // Each wrapper return this.
    abstract byte[] internalEncode();

    /**
     * Encode (aka "serialize") CBOR object to a stream.
     * <p>
     * Note: this method always produce data using 
     * <a href='package-summary.html#deterministic-encoding' class='webpkilink'>Deterministic&nbsp;Encoding</a>.
     * </p>
     * <p>
     * Note: <code>outputStream</code> is not closed after the encoding has been performed.
     * </p>
     *
     * @param outputStream Where to write data
     * @see CBORArray#encodeAsSequence()
     * @return The original <code>outputStream</code>
     */
    public OutputStream encode(OutputStream outputStream) {
        try {
            outputStream.write(internalEncode());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return outputStream;
    }

    /**
     * Encode (aka "serialize") CBOR object.
     * <p>
     * Note: this method always produce data using 
     * <a href='package-summary.html#deterministic-encoding' class='webpkilink'>Deterministic&nbsp;Encoding</a>.
     * </p>
     *
     * @see CBORArray#encodeAsSequence()
     * @return CBOR encoded <code>byte-array</code>
     */
    public byte[] encode() {
        return internalEncode();
    }

    
    abstract void internalToString(CborPrinter outputBuffer);
    
    static void nullCheck(Object object) {
        if (object == null) {
            throw new IllegalArgumentException(STDERR_ARGUMENT_IS_NULL);
        }
    }

    static CBORObject checkObject(CBORObject object) {
        nullCheck(object);
        return object;
    }

    void outOfRangeError(String type) {
        cborError(STDERR_OUT_OF_RANGE, type, this.toString());
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

    CBORObject getTypeAndMarkAsRead(Class<? extends CBORObject> requestedCborType) {
        if (requestedCborType.isInstance(this)) {
            readFlag = true;
        } else {
            cborError("Is type: " + this.getClass().getSimpleName() +
                     ", requested: " + requestedCborType.getSimpleName());
        }
        return this;
    }

    private CBORInt getCBORInt() {
        return (CBORInt) getTypeAndMarkAsRead(CBORInt.class);
    }

    /**
     * Get CBOR <code>integer</code> object.
     * <p>
     * Get CBOR integers of any size.
     * </p>
     * <p>
     * If current object is not a {@link CBORInt}, a {@link CBORException} is thrown.
     * </p>
     * 
     * @see CBORInt#CBORInt(BigInteger)
     * @return <code>BigInteger</code>
     * @throws CBORException
     */
    public BigInteger getBigInteger() {
        return getCBORInt().toBigInteger();
    }

    BigInteger checkInt128(BigInteger value, BigInteger min, BigInteger max, String type) {
        if (value.compareTo(min) < 0 || value.compareTo(max) > 0) {
            outOfRangeError(type);
        }
        return value;
    }

    /**
     * Get CBOR <code>int128</code> object.
     * <p>
     * If current object is not a
     * {@link CBORInt}, or holds a value outside the range
     * <code>-0x80000000000000000000000000000000</code> to 
     * <code>0x7fffffffffffffffffffffffffffffff</code>, a {@link CBORException} is thrown.
     * </p>
     * 
     * @see CBORInt#createInt128(BigInteger)
     * @return 128-bit signed integer.
     * @throws CBORException
     */
    public BigInteger getInt128() {
        return checkInt128(getBigInteger(), MIN_INT_128, MAX_INT_128, "Int128");
    }

    /**
     * Get CBOR <code>uint128</code> object.
     * <p>
     * If current object is not a
     * {@link CBORInt}, or holds a value outside the range
     * <code>0</code> to 
     * <code>0xffffffffffffffffffffffffffffffff</code>, a {@link CBORException} is thrown.
     * </p>
     * 
     * @see CBORInt#createUint128(BigInteger)
     * @return 128-bit unsigned integer.
     * @throws CBORException
     */
    public BigInteger getUint128() {
        return checkInt128(getBigInteger(), BigInteger.ZERO, MAX_UINT_128, "Uint128");
    } 

    /**
     * Get CBOR <code>int64</code> object.
     * <p>
     * If current object is not a
     * {@link CBORInt}, or holds a value outside the range
     * <code>-0x8000000000000000</code> to 
     * <code>0x7fffffffffffffff</code>, a {@link CBORException} is thrown.
     * </p>
     * 
     * @return <code>long</code>
     * @throws CBORException
     */
    public long getInt64() {
        CBORInt cborInt = getCBORInt();
        long value = cborInt.value;
        if (cborInt.bigValue != null || (cborInt.unsigned && (value < 0))) {
            outOfRangeError("Int64");
        }
        return value;
    }

    /**
     * Get CBOR <code>uint64</code> object.
     * <p>
     * If current object is not a
     * {@link CBORInt}, or holds a value outside the range
     * <code>0</code> to 
     * <code>0xffffffffffffffff</code>, a {@link CBORException} is thrown.
     * </p>
     * 
     * @return <code>long</code>
     * @throws CBORException
     */
    public long getUint64() {
        CBORInt cborInt = getCBORInt();
        if (cborInt.bigValue != null || !cborInt.unsigned) {
            outOfRangeError("Uint64");
        }
        return cborInt.value;
    }

    /**
     * Get CBOR <code>int53</code> object.
     * <p>
     * If current object is not a
     * {@link CBORInt}, or holds a value outside the JavaScript limits
     * <code>Number.MIN_SAFE_INTEGER</code> (<code>-9007199254740991</code>) to
     * <code>Number.MAX_SAFE_INTEGER</code> (<code>9007199254740991</code>),
     * a {@link CBORException} is thrown.
     * </p>
     * <p>
     * Since 53-bit integers are specific to JavaScript, <code>int53</code> objects
     * should be used with caution in cross-platform scenarios.
     * </p>
     * 
     * @see CBORInt#createInt53(long)
     * @return <code>long</code>
     * @throws CBORException
     */
    public long getInt53() {
        long value = getInt64();
        if (value > MAX_SAFE_JS_INTEGER || value < MIN_SAFE_JS_INTEGER) {
            outOfRangeError("Int53");
        }
        return value;
    }

    /**
     * Get CBOR <code>int32</code> object.
     * <p>
     * If current object is not a
     * {@link CBORInt}, or holds a value outside the range
     * <code>-0x80000000</code> to 
     * <code>0x7fffffff</code>, a {@link CBORException} is thrown.
     * </p>
     * 
     * @see CBORInt#createInt32(long)
     * @return <code>int</code>
     * @throws CBORException
     */
    public int getInt32() {
        long value = getInt64();
        if (value > Integer.MAX_VALUE || value < Integer.MIN_VALUE) {
            outOfRangeError("Int32");
        }
        return (int)value;
    }

    /**
     * Get CBOR <code>uint32</code> object.
     * <p>
     * If current object is not a
     * {@link CBORInt}, or holds a value outside the range
     * <code>0</code> to 
     * <code>0xffffffff</code>, a {@link CBORException} is thrown.
     * </p>
     * 
     * @see CBORInt#createUint32(long)
     * @return <code>long</code>
     * @throws CBORException
     */
    public long getUint32() {
        long value = getInt64();
        if ((value & UINT32_MASK) != 0) {
            outOfRangeError("Uint32");
        }
        return value;
    }    

    /**
     * Get CBOR <code>int16</code> object.
     * <p>
     * If current object is not a
     * {@link CBORInt}, or holds a value outside the range
     * <code>-0x8000</code> to 
     * <code>0x7fff</code>, a {@link CBORException} is thrown.
     * </p>
     * 
     * @see CBORInt#createInt16(int)
     * @return <code>int</code>
     * @throws CBORException
     */
    public int getInt16() {
        long value = getInt64();
        if (value > Short.MAX_VALUE || value < Short.MIN_VALUE) {
            outOfRangeError("Int16");
        }
        return (int)value;
    }

    /**
     * Get CBOR <code>uint16</code> object.
     * <p>
     * If current object is not a
     * {@link CBORInt}, or holds a value outside the range
     * <code>0</code> to 
     * <code>0xffff</code>, a {@link CBORException} is thrown.
     * </p>
     * 
     * @see CBORInt#createUint16(int)
     * @return <code>int</code>
     * @throws CBORException
     */
    public int getUint16() {
        long value = getInt64();
        if ((value & UINT16_MASK) != 0) {
            outOfRangeError("Uint16");
        }
        return (int)value;
    }    

    /**
     * Get CBOR <code>int8</code> object.
     * <p>
     * If current object is not a
     * {@link CBORInt}, or holds a value outside the range
     * <code>-0x80</code> to 
     * <code>0x7f</code>, a {@link CBORException} is thrown.
     * </p>
     * 
     * @see CBORInt#createInt8(int)
     * @return <code>int</code>
     * @throws CBORException
     */
    public int getInt8() {
        long value = getInt64();
        if (value > Byte.MAX_VALUE || value < Byte.MIN_VALUE) {
            outOfRangeError("Int8");
        }
        return (int)value;
    }

    /**
     * Get CBOR <code>uint8</code> object.
     * <p>
     * If current object is not a
     * {@link CBORInt}, or holds a value outside the range
     * <code>0</code> to 
     * <code>0xff</code>, a {@link CBORException} is thrown.
     * </p>
     * 
     * @see CBORInt#createUint8(int)
     * @return <code>int</code>
     * @throws CBORException
     */
    public int getUint8() {
        long value = getInt64();
        if ((value & UINT8_MASK) != 0) {
            outOfRangeError("Uint8");
        }
        return (int)value;
    }

    /**
     * Get "extended" CBOR <code>float</code> object.
     * <p>
     * If current object is not a
     * {@link CBORFloat} holding a 64, 32, or 16-bit
     * <span style='white-space:nowrap'><code>IEEE</code> <code>754</code></span> number, 
     * a {@link CBORException} is thrown.
     * </p>
     * <p>
     * Note that unlike {@link #getFloat64()}, this method also supports the
     * {@link Double#NaN},
     * {@link Double#POSITIVE_INFINITY}, and 
     * {@link Double#NEGATIVE_INFINITY} non-finite variants.
     * </p>
     * 
     * @return <code>double</code>
     * @throws CBORException
     * @see CBORFloat#createExtendedFloat(double)
     */
    public double getExtendedFloat64() {
        if (this instanceof CBORNonFinite nf) {
            return switch (nf.isSimple() ? (int)nf.getNonFinite() : 0) {
                case 0x7e00 -> Double.NaN;
                case 0x7c00 -> Double.POSITIVE_INFINITY;
                case 0xfc00 -> Double.NEGATIVE_INFINITY;
                default -> {
                    cborError(STDERR_ONLY_SIMPLE_NAN);
                    yield 0.0;
                }
            };
        }
        return getFloat64();
    }

    /**
     * Get CBOR <code>float</code> object.
     * <p>
     * If current object is not a
     * {@link CBORFloat} holding a 64, 32, or 16-bit
     * <span style='white-space:nowrap'><code>IEEE</code> <code>754</code></span> number, 
     * a {@link CBORException} is thrown.
     * </p>
     * <p>
     * Unlike {@link #getExtendedFloat64()}, this method only accepts "regular" floating-point
     * numbers.  This makes it adapted for CBOR protocols that do not consider <code>NaN</code>
     * or <code>Infinity</code> as valid items.  That is, the latter cause a {@link CBORException}
     * to be thrown.
     * </p>
     * 
     * @return <code>double</code>
     * @throws CBORException
     */
    public double getFloat64() {
        return ((CBORFloat) getTypeAndMarkAsRead(CBORFloat.class)).value;
    }
 
    /**
     * Get CBOR <code>float32</code> object.
     * <p>
     * If current object is not a
     * {@link CBORFloat} holding a 32-bit or 16-bit 
     * <span style='white-space:nowrap'><code>IEEE</code> <code>754</code></span> number, 
     * a {@link CBORException} is thrown.
     * </p>
     * 
     * @see CBORFloat#createFloat32(double)
     * @return <code>float</code>
     * @throws CBORException
     */
    public float getFloat32() {
        CBORFloat floatingPoint = (CBORFloat) getTypeAndMarkAsRead(CBORFloat.class);
        if (floatingPoint.tag == MT_FLOAT64) {
            outOfRangeError("Float32");
        }
        return (float)floatingPoint.value;
    }

    /**
     * Get CBOR <code>float16</code> object.
     * <p>
     * If current object is not a
     * {@link CBORFloat} holding a 16-bit
     * <span style='white-space:nowrap'><code>IEEE</code> <code>754</code></span> number, 
     * a {@link CBORException} is thrown.
     * </p>
     * 
     * @see CBORFloat#createFloat16(double)
     * @return <code>float</code>
     * @throws CBORException
     */
    public float getFloat16() {
        CBORFloat floatingPoint = (CBORFloat) getTypeAndMarkAsRead(CBORFloat.class);
        if (floatingPoint.tag != MT_FLOAT16) {
            outOfRangeError("Float16");
        }
        return (float)floatingPoint.value;
    }

    /**
     * Get CBOR <code>#7.n</code> (simple) object.
     * <p>
     * If current object is not a
     * {@link CBORSimple}, a {@link CBORException} is thrown.
     * </p>
     * 
     * @return <code>int</code>
     * @throws CBORException
     */
    public int getSimple() {
        return ((CBORSimple) getTypeAndMarkAsRead(CBORSimple.class)).value;
    }

    /**
     * Get CBOR <code>bool</code> object.
     * <p>
     * If current object is not a
     * {@link CBORBoolean}, a {@link CBORException} is thrown.
     * </p>
     * 
     * @return <code>boolean</code>
     * @throws CBORException
     */
    public boolean getBoolean() {
        return ((CBORBoolean) getTypeAndMarkAsRead(CBORBoolean.class)).value;
    }

    /**
     * Check for CBOR <code>null</code>.
     * <p>
     * If current object is a {@link CBORNull} the call will return
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
        if (this instanceof CBORNull) {
            readFlag = true;
            return true;
        }
        return false;
    }
    
    /**
     * Get CBOR <code>tstr</code> object.
     * <p>
     * If current object is not a 
     * {@link CBORString}, a {@link CBORException} is thrown.
     * </p>
      * 
     * @return <code>String</code>
     * @throws CBORException
     */
    public String getString() {
        return ((CBORString) getTypeAndMarkAsRead(CBORString.class)).textString;
    }

    /**
     * Get <code>EpochTime</code> object.
     *
     * <div style='margin-top:0.5em'>
     * Depending on the type of the current object, this method performs a
     * {@link #getInt64()} or a {@link #getFloat64()}.
     * The returned number is subsequently used for initiating an {@link Instant} object.</div>
     * <div style='margin-top:0.5em'>
     * If not <i>all</i> of the following conditions are met,
     * a {@link CBORException} is thrown:
     * <ul style='padding:0;margin:0 0 0.5em 1.2em'>
     * <li style='margin-top:0'>The underlying object
     * is a {@link CBORInt} or {@link CBORFloat}.</li>
     * <li>The Epoch 
     * [<a href='https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html#tag_04_19'
     * class='webpkilink'>TIME</a>] object is within the range:
     * <span style='white-space:nowrap'><code>0</code> 
     * (<code>"1970-01-01T00:00:00Z"</code>)</span> to
     * <span style='white-space:nowrap'><code>253402300799</code> 
     * (<code>"9999-12-31T23:59:59Z"</code>)</span>.</li>
     * </ul>
     * </div>
     * 
     * @return {@link Instant}
     * @see CBORTag#getEpochTime()
     * @see CBORUtil#createEpochTime(Instant, boolean)
     * @throws CBORException
     */
    public Instant getEpochTime() {
        double epochSeconds = this instanceof CBORInt ? (double) getInt64() : getFloat64();
        if (epochSeconds < 0 || epochSeconds > (MAX_INSTANT_IN_MILLIS / 1000L)) {
            CBORUtil.epochOutOfRange(epochSeconds);
        }
        return Instant.ofEpochMilli(Math.round(epochSeconds * 1000));
    }

    static final Pattern RFC3339_5_6_PATTERN = Pattern.compile(
            "(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(\\.\\d{1,9})?([+-]\\d{2}:\\d{2}|Z)");
    /**
     * Get <code>DateTime</code> object.
     * 
     * <div style='margin-top:0.5em'>
     * This method performs a {@link #getString()}.
     * The returned string is subsequently used for initiating an {@link Instant} object.</div>
     * <div style='margin-top:0.5em'>
     * If not <i>all</i> of the following conditions are met, a {@link CBORException} is thrown:
     * <ul style='padding:0;margin:0 0 0.5em 1.2em'>
     * <li style='margin-top:0'>The underlying object is a
     * {@link CBORString}.</li>
     * <li>The string matches the ISO date/time format described
     * in section&nbsp;5.6 of
     * [<a href='https://www.rfc-editor.org/rfc/rfc3339.html#section-5.6' class='webpkilink'>RFC3339</a>].</li>
     * <li>The <i>optional</i> sub-second field (<code>.nnn</code>) 
     * features <i>less</i> than ten digits.</li>
     * <li>The date/time object is within the range:
     * <code style='white-space:nowrap'>"0000-01-01T00:00:00Z"</code> to
     * <code style='white-space:nowrap'>"9999-12-31T23:59:59Z"</code>.</li>
     * </ul>
     * </div>
     *
     * @return {@link Instant}
     * @throws CBORException
     * @see CBORTag#getDateTime()
     * @see CBORUtil#createDateTime(Instant, boolean, boolean)
     */
    public Instant getDateTime() {
        String dateTime = getString();
        if (!RFC3339_5_6_PATTERN.matcher(dateTime).matches()) {
            cborError("\"DateTime\" syntax error: " + dateTime);
        }
        Instant instant = ZonedDateTime.parse(dateTime).toInstant();
        CBORUtil.instantDateTimeToMillisCheck(instant);
        return instant;
    }

    /**
     * Get CBOR <code>bstr</code> object.
     * <p>
     * If current object is not a
     * {@link CBORBytes}, a {@link CBORException} is thrown.
     * </p>
     * 
     * @return <code>byteArray</code>
     * @throws CBORException
     */
    public byte[] getBytes() {
        return ((CBORBytes) getTypeAndMarkAsRead(CBORBytes.class)).byteString;
    }

    /**
     * Get handle to CBOR <code>{}</code> (map) object.
     * <p>
     * If current object is not a
     * {@link CBORMap}, a {@link CBORException} is thrown.
     * </p>
     * <p>
     * Note: do not replace this method with a cast!
     * </p>
     * 
     * @return CBOR <code>{}</code> (map) object
     * @throws CBORException
     */
    public CBORMap getMap() {
        return (CBORMap) getTypeAndMarkAsRead(CBORMap.class);
    }

    /**
     * Get handle to CBOR <code>[]</code> (array) object.
     * <p>
     * If current object is not a
     * {@link CBORArray}, a {@link CBORException} is thrown.
     * </p>
     * <p>
     * Note: do not replace this method with a cast!
     * </p>
     * 
     * @return CBOR <code>[]</code> (array) object
     * @throws CBORException
     */
    public CBORArray getArray() {
        return (CBORArray) getTypeAndMarkAsRead(CBORArray.class);
    }
    
    /**
     * Get handle to CBOR <code>#6.n</code> (tag) object.
     * <p>
     * If current object is not a
     * {@link CBORTag}, a {@link CBORException} is thrown.
     * </p>
     * <p>
     * Note: do not replace this method with a cast!
     * </p>
     * 
     * @return CBOR <code>#6.n</code> (tag) object
     * @throws CBORException
     */
    public CBORTag getTag() {
        return (CBORTag) getTypeAndMarkAsRead(CBORTag.class);
    }

    static void makeImmutable(CBORObject object) {
        object.immutableFlag = true;
        if (object instanceof CBORMap cborMap) {
            for (CBORMap.Entry entry : cborMap.entries) {
                makeImmutable(entry.object);
            }
        } else if (object instanceof CBORArray cborArray) {
            for (CBORObject value : cborArray.objects) {
                makeImmutable(value);
            }
        }
    }

    void immutableTest() {
        if (immutableFlag) {
            cborError(STDERR_MAP_KEY_IMMUTABLE);
        }
    }

    /**
     * Scan CBOR object and mark it as read.
     * <p>
     * This method sets the status of the current object as well as to possible
     * child objects to &quot;read&quot;.
     * </p>
     * 
     * @see #checkForUnread()
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
     * 
     * @see #scan()
     * @throws CBORException
     */
    public void checkForUnread() {
        traverse(null, true);
    }

    private void traverse(CBORObject holderObject, boolean check) {
        // Should use a switch but Android didn't accept it :(
        if (this instanceof CBORMap cborMap) {
            for (CBORMap.Entry entry : cborMap.entries) {
                entry.object.traverse(entry.key, check);
            }
        } else if (this instanceof CBORArray cborArray) {
            for (CBORObject object : cborArray.objects) {
                object.traverse(cborArray, check);
            }
        } else if (this instanceof CBORTag cborTag) {
            cborTag.object.traverse(cborTag, check);
        }
        if (check) {
            if (!readFlag) {
                cborError((holderObject == null ? "Data" : 
                            holderObject instanceof CBORArray ? "Array element" :
                                holderObject instanceof CBORTag ?
                                "Tagged object " +
                                Long.toUnsignedString(((CBORTag)holderObject).tagNumber) : 
                                "Map key " + holderObject.toDiagnostic(false) + " with argument") +                    
                            " of type=" + this.getClass().getSimpleName() + 
                            " with value=" + this.toDiagnostic(false) + " was never read");
            }
        } else {
            readFlag = true;
        }
    }
    
    static class CborPrinter {
 
        static final String INDENT       = "  ";
        static final int MAX_LINE_LENGTH = 70;  // RFCs
        
        private int indentationLevel;
        private StringBuilder outputBuffer;
        private boolean prettyPrint;
        private int startOfLine;
               
        private CborPrinter(boolean prettyPrint) {
            outputBuffer = new StringBuilder();
            this.prettyPrint = prettyPrint;
        }

        void newlineAndIndent() {
            if (prettyPrint) {
                startOfLine = outputBuffer.length();
                outputBuffer.append('\n');
                for (int i = 0; i < indentationLevel; i++) {
                    outputBuffer.append(INDENT);
                }
            }
        }

        boolean arrayFolding(CBORArray array) {
            if (prettyPrint) {
                if (array.size() == 0) {
                    return false;
                }
                boolean arraysInArrays = true;
                for (CBORObject element : array.toArray()) {
                    if (!(element instanceof CBORArray)) {
                        arraysInArrays = false;
                        break;
                    }
                }
                if (arraysInArrays) {
                    return true;
                }
                if (outputBuffer.length() - startOfLine + // Where we are staing at the moment.
                    array.size() +                        // space after comma.
                    2 +                                   // [] 
                    array.toDiagnostic(false).length() > MAX_LINE_LENGTH) {
                    return true;
                }
            }
            return false;
        }
        
        void beginList(char startChar) {
            outputBuffer.append(startChar);
            indentationLevel++;
        }
        
        void space() {
            if (prettyPrint) {
                outputBuffer.append(' ');
            }
        }

        void endList(boolean notEmpty, char endChar) {
            indentationLevel--;
            if (notEmpty) {
                newlineAndIndent();
            }
            outputBuffer.append(endChar);
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
     * <p>
     * The result is <code>true</code> if and only if the argument is
     * not <code>null</code> and is a {@link CBORObject}, and the associated
     * binary encodings (as provided by {@link #encode()}) are equivalent.
     * </p>
     * @param object Argument to compare with
     */
    @Override
    public boolean equals(Object object) {
        return object instanceof CBORObject o && Arrays.equals(o.encode(), encode());
    }

    /**
     * Compare CBOR objects for magnitude.
     * <p>
     * The comparison is based on the associated binary encodings as provided by {@link #encode()}.
     * </p>
     * @param object Argument to compare with
     */
    @Override
    public int compareTo(CBORObject object) {
        return Arrays.compareUnsigned(encode(), object.encode());
    }

    /**
     * Calculate hash code of CBOR object.
     * <p>
     * The hash is calculated in the same way as for {@link String#hashCode()},
     * using the output from {@link #encode()} as <code>"s"</code>.
     * </p>
     */
    @Override
    public int hashCode() {
        byte[] encoded = encode();
        int hash = 0;
        for (byte b : encoded) {
            hash = 31 * hash + (b & 0xff);
        }
        return hash;
    }

    /**
     * Render CBOR object in
     * <a href='package-summary.html#diagnostic-notation' class='webpkilink'>Diagnostic Notation</a>.
     * <p>
     * If current object (as well as possible
     * child objects), conforms to the subset of data types supported by JSON,
     * this method can also be used to generate JSON data.
     * </p>
     * @param prettyPrint If <code>true</code> white space is added to make the 
     * result easier to read.  If <code>false</code> elements are output
     * without additional white space (=single line).
     */
    public String toDiagnostic(boolean prettyPrint) {
        CborPrinter outputBuffer = new CborPrinter(prettyPrint);
        internalToString(outputBuffer);
        return outputBuffer.getTextualCbor();
    }

    /**
     * Render CBOR object in a pretty-printed form.
     * <p>
     * Equivalent to {@link #toDiagnostic(boolean)}
     * with the argument set to <code>true</code>.
     * </p>
     */
    @Override
    public String toString() {
        return toDiagnostic(true);
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
        return CBORDecoder.decode(encode());
    }

    static final String STDERR_OUT_OF_RANGE =
            "Value out of range for \"%s\": %s";
    
    static final String STDERR_ARGUMENT_IS_NULL =
            "Argument \"null\" is not permitted";

    static final String STDERR_MAP_KEY_IMMUTABLE =
            "Map keys are immutable";

   static final String STDERR_ONLY_SIMPLE_NAN =
            "getExtendedFloat64() only supports \"simple\" NaN (7e00)";

}
