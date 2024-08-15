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

import static org.webpki.cbor.CBORInternal.*;

/**
 * Base class for all CBOR objects.
 * <p>
 * In this implementation "object" should be regarded as equivalent to the RFC 8949 "data item".
 * </p>
 */
public abstract class CBORObject implements Cloneable, Comparable<CBORObject> {
    
    CBORTypes cborType;
    
    CBORObject(CBORTypes cborType) {
        this.cborType = cborType;
    }
    
    // True if object has been read
    private boolean readFlag;
    
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

    static CBORArray checkCOTX(CBORObject taggedObject) {
        CBORArray holder = taggedObject.cborType == CBORTypes.ARRAY ? 
                                            taggedObject.getArray() : null;
        if (holder == null || holder.size() != 2 || holder.get(0).cborType != CBORTypes.STRING) {
            cborError("Invalid COTX object: " + taggedObject.toDiagnosticNotation(false));
        }
        return holder;
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
            integerRangeError("Int64");
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
            integerRangeError("Uint64");
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
            integerRangeError("Int32");
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
        long value = getInt64();
        if ((value & UINT32_MASK) != 0) {
            integerRangeError("Uint32");
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
            integerRangeError("Int16");
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
        long value = getInt64();
        if ((value & UINT16_MASK) != 0) {
            integerRangeError("Uint16");
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
            integerRangeError("Int8");
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
        long value = getInt64();
        if ((value & UINT8_MASK) != 0) {
            integerRangeError("Uint8");
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

}
