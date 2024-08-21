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

import org.webpki.util.UTF8;

import static org.webpki.cbor.CBORInternal.*;

/**
 * CBOR decoder class.
 */
public class CBORDecoder {
   
    private InputStream inputStream;
    private boolean sequenceFlag;
    private boolean deterministicMode = true;
    private boolean rejectNaNFlag;
    private boolean atFirstByte;
    private int maxLength = Integer.MAX_VALUE;
    private int byteCount;

    /**
    * Create a parameterized CBOR decoder.
    * <p>
    * See {@link CBORDecoder#setDeterminismMode(boolean)},
    * {@link CBORDecoder#setInputLength(int)},
    * {@link CBORDecoder#setNaNSupport(boolean)}, and
    * {@link CBORDecoder#setSequenceMode(boolean)}
    * </p>
    * <p>
    * To be used with {@link CBORDecoder#decodeWithOptions()}.
    * </p>
    * @param inputStream Stream holding CBOR data. 
    */
    public CBORDecoder(InputStream inputStream) {
        this.inputStream = inputStream;
    }
    
    private void eofError() {
        cborError(STDERR_CBOR_EOF);
    }

    private void unsupportedTag(int tag) {
        cborError(String.format(STDERR_UNSUPPORTED_TAG + "%02x", tag));
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
        if (deterministicMode &&
            (cborFloat.tag != tag || cborFloat.bitFormat != bitFormat)) {
            cborError(String.format(STDERR_NON_DETERMINISTIC_FLOAT + "%2x", tag));
        }
        if (rejectNaNFlag && cborFloat.tag == MT_FLOAT16 &&
            (cborFloat.bitFormat & FLOAT16_POS_INFINITY) == FLOAT16_POS_INFINITY) {
            cborError(STDERR_INVALID_FLOAT_DISABLED);
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
                BigInteger bigInteger = new BigInteger(1, byteArray);
                if (deterministicMode) {
                    if (byteArray.length <= 8 || byteArray[0] == 0) {
                        cborError(STDERR_NON_DETERMINISTIC_BIGNUM);
                    }
                } else {
                    // Potentially sloppy serialization.
                    if (bigInteger.compareTo(MAX_CBOR_INTEGER_MAGNITUDE) < 1) {
                        return new CBORInt(bigInteger.longValue(), tag == MT_BIG_UNSIGNED);
                    }
                }
                return new CBORBigInt(tag == MT_BIG_UNSIGNED ? bigInteger : bigInteger.not());

            case MT_FLOAT16:
                double float64;
                long f16Binary = getLongFromBytes(2);

                // Get the significand.
                long significand = f16Binary & ((1L << FLOAT16_SIGNIFICAND_SIZE) - 1);
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
                        significand += (1L << FLOAT16_SIGNIFICAND_SIZE);
                        // -1: Keep fractional point in line with subnormal numbers.
                        significand <<= ((exponent >> FLOAT16_SIGNIFICAND_SIZE) - 1);
                    }
                    // Divide with: (2 ^ (Exponent offset + Size of significand - 1)).
                    float64 = (double)significand / 
                            (1L << (FLOAT16_EXPONENT_BIAS + FLOAT16_SIGNIFICAND_SIZE - 1));
                }
                return checkDoubleConversion(tag,
                                             f16Binary,
                                             f16Binary >= FLOAT16_NEG_ZERO ? -float64 : float64);

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
        long n = tag & 0x1fL;
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
            if (deterministicMode && ((n & mask) == 0 || (n > 0 && n < 24))) {
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

    /**
     * Decode CBOR data with options.
     * @return {@link CBORObject} or <code>null</code> (for EOF sequences only).
     * @throws CBORException For decoding errors.
     */
    public CBORObject decodeWithOptions() {        
        try {
            atFirstByte = true;
            CBORObject cborObject = getObject();
            if (sequenceFlag) {
                if (atFirstByte) {
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
     * Get CBOR decoder byte count.
     * <p>
     * This is equivalent to the position of the next item to be read.
     * </p>
     * @return The number of bytes read so far.
     */
    public int getByteCount() {
        return byteCount;
    }

    /**
     * Set CBOR decoder input max length.
     * <p>
     * By default the CBOR decoder accepts up to ({@link Integer#MAX_VALUE}
     * bytes of input data.
     * Since malformed CBOR objects can request arbitrary amounts of memory,
     * it is <i>highly recommended</i> to select a value that is adapted to
     * the actual application.
     * This method enables overriding the default.
     * </p>
     * @param maxLength Maximum length of CBOR input in bytes.
     * Exceeding this limit will cause a {@link CBORException} to be thrown.
     * @return <code>this</code> (updated {@link CBORDecoder} object)
     */
    public CBORDecoder setInputLength(int maxLength) {
        this.maxLength = maxLength;
        return this;
    }

    /**
     * Set CBOR decoder <code>NaN/Infinity</code> support.
     * <p>
     * By default the decoder supports 
     * <code>NaN</code>, <code>Infinity</code>, 
     * and <code style='white-space:nowrap'>-Infinity</code>. 
     * In case these variants are not applicable for the application in question,
     * this method enables overriding the default.
     * </p>
     * @param reject If the <code>reject</code> flag is set to <code>true</code>,
     * the mentioned exceptional floating point values will (if encountered),
     * cause a {@link CBORException} to be thrown.
     * @return <code>this</code> (updated {@link CBORDecoder} object)
     */
    public CBORDecoder setNaNSupport(boolean reject) {
        this.rejectNaNFlag = reject;
        return this;
    }

    /**
     * Set CBOR decoder determinism mode.
     * <p>
     * By default the decoder assumes that CBOR data conforms to the
     * <a href='package-summary.html#deterministic-encoding'>Deterministic&nbsp;Encoding</a> rules.
     * This method enables overriding the default.
     * </p>
     * @param enforce If the <code>enforce</code> flag is set to <code>false</code>,
     * the decoder will accept CBOR data that does not adhere to the map sorting
     * and preferred number serialization requirements.
     * This option may be needed for dealing with &quot;legacy&quot; CBOR implementations.
     * Note: duplicate keys and other invalid (or not supported) CBOR constructs
     * will still cause a {@link CBORException} to be thrown.
     * @return <code>this</code> (updated {@link CBORDecoder} object)
     */
    public CBORDecoder setDeterminismMode(boolean enforce) {
        this.deterministicMode = enforce;
        return this;
    }
 
    /**
     * Set CBOR decoder sequence mode.
     * <p>
     * By default the decoder assumes that CBOR data constitutes
     * of a single CBOR object.
     * This method enables overriding the default.
     * </p>
     * <p>
     * Also see {@link CBORSequenceBuilder}.
     * </p>
     * @param sequence If the <code>sequence</code> flag is set to <code>true</code>,
     * the following apply:
     * <ul>
     * <li>Immediately return after decoding a CBOR object, while preparing the 
     * decoder for the next item.
     * See also {@link #getByteCount()}.</li>
     * <li>If no data is found (EOF), <code>null</code> is returned
     * (<i>empty</i> sequences are permitted).</li>
     * <li>Note that data <i>succeeding</i> a just decoded CBOR object 
     * is not verified for correctness.</li>  
     * </ul>
     * @return <code>this</code> (updated {@link CBORDecoder} object)
     */
    public CBORDecoder setSequenceMode(boolean sequence) {
        this.sequenceFlag = sequence;
        return this;
    }

    /**
     * Decode CBOR data.
     * <p>
     * This conveniance method is identical to:
     * <pre>  new CBORDecoder(new ByteArrayInputStream(cbor))
     *      .setInputLength(cbor.length)
     *      .decodeWithOptions();
     * </pre>
     * </p>
     * @param cbor CBOR binary data <i>holding exactly one CBOR object</i>.
     * @return {@link CBORObject}
     * @throws CBORException For decoding errors.
     */
    public static CBORObject decode(byte[] cbor) {
        return new CBORDecoder(new ByteArrayInputStream(cbor))
                                   .setInputLength(cbor.length)
                                   .decodeWithOptions();
    }
    
    static final String STDERR_UNSUPPORTED_TAG =
            "Unsupported tag: ";

    static final String STDERR_N_RANGE_ERROR =
            "N out of range: ";

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

    static final String STDERR_INVALID_FLOAT_DISABLED = 
            "\"NaN\" and \"Infinity\" support is disabled";
}
