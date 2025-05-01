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

import java.util.Arrays;
import java.util.GregorianCalendar;

import org.webpki.util.ISODateTime;

import static org.webpki.cbor.CBORInternal.*;

/**
 * Base class for all CBOR objects.
 * <p>
 * In this implementation "object" should be regarded as 
 * equivalent to the  
 * CBOR [<a href='https://www.rfc-editor.org/rfc/rfc8949.html'>RFC&nbsp;8949</a>]
 * term, "data item".
 * </p>
 */
public abstract class CBORObject implements Cloneable, Comparable<CBORObject> {

    // Package level constructor
    CBORObject() {}
    
    // True if object has been read
    private boolean readFlag;

    // True if map key object
    private boolean immutableFlag;

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

    void checkTypeAndMarkAsRead(Class<? extends CBORObject> requestedCborType) {
        if (requestedCborType.isInstance(this)) {
            readFlag = true;
        } else {
            cborError("Is type: " + this.getClass().getSimpleName() +
                     ", requested: " + requestedCborType.getSimpleName());
        }
    }

    private CBORInt getCBORInt() {
        checkTypeAndMarkAsRead(CBORInt.class);
        return (CBORInt) this;
    }

    /**
     * Get CBOR <code>bigint</code> value.
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
        if (this instanceof CBORInt) {
            return getCBORInt().toBigInteger();
        }
        checkTypeAndMarkAsRead(CBORBigInt.class);
        return ((CBORBigInt) this).value;
    }

    /**
     * Get CBOR <code>int</code> value.
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
        long value = CBORInt.value;
        if (CBORInt.unsigned && (value < 0)) {
            integerRangeError("Int64");
        }
        return value;
    }

    /**
     * Get CBOR <code>uint</code> value.
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
            integerRangeError("Uint64");
        }
        return CBORInt.value;
    }

    /**
     * Get CBOR <code>int</code> value.
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
            integerRangeError("Int32");
        }
        return (int)value;
    }

    /**
     * Get CBOR <code>uint</code> value.
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
        long value = getInt64();
        if ((value & UINT32_MASK) != 0) {
            integerRangeError("Uint32");
        }
        return value;
    }    

    /**
     * Get CBOR <code>int</code> value.
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
            integerRangeError("Int16");
        }
        return (int)value;
    }

    /**
     * Get CBOR <code>uint</code> value.
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
        long value = getInt64();
        if ((value & UINT16_MASK) != 0) {
            integerRangeError("Uint16");
        }
        return (int)value;
    }    

    /**
     * Get CBOR <code>int</code> value.
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
            integerRangeError("Int8");
        }
        return (int)value;
    }

    /**
     * Get CBOR <code>uint</code> value.
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
        long value = getInt64();
        if ((value & UINT8_MASK) != 0) {
            integerRangeError("Uint8");
        }
        return (int)value;
    }    

    /**
     * Get CBOR <code>float64</code> value.
     * <p>
     * This method requires that the object is a
     * {@link CBORFloat}, otherwise a {@link CBORException} is thrown.
     * </p>
     * 
     * @return <code>double</code>
     * @throws CBORException
     */
    public double getFloat64() {
        checkTypeAndMarkAsRead(CBORFloat.class);
        return ((CBORFloat) this).value;
    }
 
    /**
     * Get CBOR <code>float32</code> value.
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
        checkTypeAndMarkAsRead(CBORFloat.class);
        CBORFloat floatingPoint = (CBORFloat) this;
        if (floatingPoint.tag == MT_FLOAT64) {
            cborError(STDERR_FLOAT_RANGE);
        }
        return (float)floatingPoint.value;
    }

    /**
     * Get CBOR <code>float16</code> value.
     * <p>
     * This method requires that the object is a
     * {@link CBORFloat} holding a 16-bit IEEE 754 value, 
     * otherwise a {@link CBORException} is thrown.
     * </p>
     * 
     * @return <code>float</code>
     * @throws CBORException
     */
    public float getFloat16() {
        checkTypeAndMarkAsRead(CBORFloat.class);
        CBORFloat floatingPoint = (CBORFloat) this;
        if (floatingPoint.tag != MT_FLOAT16) {
            cborError(STDERR_FLOAT_RANGE);
        }
        return (float)floatingPoint.value;
    }
    /**
     * Get CBOR <code>#7.n</code> (simple) value.
     * <p>
     * This method requires that the object is a
     * {@link CBORSimple}, 
     * otherwise a {@link CBORException} is thrown.
     * </p>
     * @return <code>int</code>
     * @throws CBORException
     */
    public int getSimple() {
        checkTypeAndMarkAsRead(CBORSimple.class);
        return ((CBORSimple) this).value;
    }

    /**
     * Get CBOR <code>bool</code> value.
     * <p>
     * This method requires that the object is a
     * {@link CBORBoolean}, otherwise a {@link CBORException} is thrown.
     * </p>
     * 
     * @return <code>boolean</code>
     * @throws CBORException
     */
    public boolean getBoolean() {
        checkTypeAndMarkAsRead(CBORBoolean.class);
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
        if (this instanceof CBORNull) {
            readFlag = true;
            return true;
        }
        return false;
    }
    
    /**
     * Get CBOR <code>tstr</code> object.
     * <p>
     * This method requires that the object is a 
     * {@link CBORString}, otherwise a {@link CBORException} is thrown.
     * </p>
      * 
     * @return <code>String</code>
     * @throws CBORException
     */
    public String getString() {
        checkTypeAndMarkAsRead(CBORString.class);
        return ((CBORString) this).textString;
    }

    /**
     * Get UNIX <code>Epoch</code> time object.
     * <p>
     * This method requires that the underlying object is a 
     * {@link CBORInt} or {@link CBORFloat}, 
     * otherwise a {@link CBORException} is thrown.
     * </p>
      * 
     * @return <code>GregorianCalendar</code>
     * @see CBORTag#getEpochTime()
     * @throws CBORException
     */
    public GregorianCalendar getEpochTime() {
        long timeInMillis = this instanceof CBORInt ? 
                                  getInt64() * 1000 : Math.round(getFloat64() * 1000);
        GregorianCalendar gregorianCalendar = new GregorianCalendar();
        gregorianCalendar.setTimeInMillis(timeInMillis);
        return gregorianCalendar;
    }

    /**
     * Get ISO <code>date/time</code> object.
     * <p>
     * This method requires that the underlying object is a 
     * {@link CBORString} that is compatible with ISO date/time
     * [<a href='https://www.rfc-editor.org/rfc/rfc3339.html'>RFC&nbsp;3339</a>], 
     * otherwise a {@link CBORException} is thrown.
     * </p>
      * 
     * @return <code>GregorianCalendar</code>
     * @throws CBORException
     * @throws IllegalArgumentException
     * @see CBORTag#getDateTime()
     */
    public GregorianCalendar getDateTime() {
        return ISODateTime.decode(getString(), ISODateTime.COMPLETE);
    }

    /**
     * Get CBOR <code>bstr</code> object.
     * <p>
     * This method requires that the object is a
     * {@link CBORBytes}, otherwise a {@link CBORException} is thrown.
     * </p>
     * 
     * @return <code>byteArray</code>
     * @throws CBORException
     */
    public byte[] getBytes() {
        checkTypeAndMarkAsRead(CBORBytes.class);
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
        checkTypeAndMarkAsRead(CBORMap.class);
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
        checkTypeAndMarkAsRead(CBORArray.class);
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
        checkTypeAndMarkAsRead(CBORTag.class);
        return (CBORTag) this;
    }

    void makeImmutable(CBORObject object) {
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
     * This method sets the status of this object as well as to possible
     * child objects to &quot;read&quot;.
     * </p>
     * See also {@link #checkForUnread()}.
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
     * See also {@link #scan()}.
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
                                "Map key " + holderObject.toDiagnosticNotation(false) + " with argument") +                    
                            " of type=" + this.getClass().getSimpleName() + 
                            " with value=" + this.toDiagnosticNotation(false) + " was never read");
            }
        } else {
            readFlag = true;
        }
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
     * <p>
     * Equality in CBOR depends on the actual binary encoding which in turn depends on
     * <a href='package-summary.html#deterministic-encoding'>Deterministic&nbsp;Encoding</a>.
     * </p>
     */
    @Override
    public boolean equals(Object object) {
        return object instanceof CBORObject ? 
            Arrays.equals(((CBORObject) object).encode(), encode()) : false;
    }

    /**
     * Compare CBOR objects for magnitude.
     */
    @Override
    public int compareTo(CBORObject object) {
        return Arrays.compareUnsigned(encode(), object.encode());
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
        return CBORDecoder.decode(encode());
    }

    static final String STDERR_INT_RANGE =
            "CBOR integer does not fit a Java \"";
    
    static final String STDERR_ARGUMENT_IS_NULL =
            "Argument \"null\" is not permitted";

    static final String STDERR_FLOAT_RANGE =
            "Value out of range for \"float\"";

    static final String STDERR_MAP_KEY_IMMUTABLE =
            "Map keys are immutable";

}
