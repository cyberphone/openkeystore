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

    /**
     * {@link CBORDecoder#CBORDecoder(InputStream, int, int)} <code>options</code> flag.
     */
    public final static int SEQUENCE_MODE            = 0x1;

    /**
     * {@link CBORDecoder#CBORDecoder(InputStream, int, int)} <code>options</code> flag.
     */
    public final static int LENIENT_MAP_DECODING     = 0x2;

    /**
     * {@link CBORDecoder#CBORDecoder(InputStream, int, int)} <code>options</code> flag.
     */
    public final static int LENIENT_NUMBER_DECODING  = 0x4;


    static final BigInteger NEGATIVE_HIGH_RANGE = new BigInteger("-10000000000000000", 16);
   
    private InputStream inputStream;
    private boolean sequenceMode;
    private boolean strictMaps;
    private boolean strictNumbers;
    private boolean atFirstByte;
    private int maxInputLength;
    private int byteCount;

    /**
    * Create a customized CBOR decoder.
    * <p>
    * Note that irrespective of options, the decoder maintains parsed data
    * in the form required for  
    * <a href='package-summary.html#deterministic-encoding' class='webpkilink'>Deterministic&nbsp;Encoding</a>.
    * </p>
    * <p>
    * This constructor presumes that the actual decoding is performed
    * by one or more (for sequences only) calls to {@link #decodeWithOptions()}.
    * </p>
    * <p>
    * Customization is provided through an <code>options</code> parameter.
    * Multiple options can be combined using the binary OR-operator ("<code>|</code>").
    * A zero (0) sets the decoder default mode.
    * The options are defined by the following constants:
    * </p>
    * <div style='margin-top:0.3em'>{@link CBORDecoder#SEQUENCE_MODE}:</div>
    * <div style='padding:0.2em 0 0 1.2em'>If the {@link CBORDecoder#SEQUENCE_MODE}
    * option is defined, the following apply:
    * <ul style='padding:0;margin:0 0 0.5em 1.2em'>
    * <li style='margin-top:0'>The decoder returns after having decoded
    * a <i>single</i> CBOR object, while preparing for the next object.</li>
    * <li>If no data is found (EOF), <code>null</code> is returned
    * (<i>empty</i> sequences are permitted).</li>
    * </ul>
    * Note that data that has not yet been decoded, is not verified for correctness.
    * <div style='margin-top:0.5em'>See also {@link CBORArray#encodeAsSequence}.</div></div>
    *
    * <div style='margin-top:0.8em'>{@link CBORDecoder#LENIENT_MAP_DECODING}:</div>
    * <div style='padding:0.2em 0 0 1.2em'>By default, the decoder requires
    * that CBOR maps conform to the
    * <a href='package-summary.html#deterministic-encoding' class='webpkilink'>Deterministic&nbsp;Encoding</a> 
    * rules.
    * <div>The {@link CBORDecoder#LENIENT_MAP_DECODING} option forces the decoder
    * to accept CBOR maps with arbitrary key ordering.
    * Note that duplicate keys still cause a {@link CBORException} to be thrown.</div></div>
    *
    * <div style='margin-top:0.8em'>{@link CBORDecoder#LENIENT_NUMBER_DECODING}:</div>
    * <div style='padding:0.2em 0 0 1.2em'>By default, the decoder requires
    * that CBOR numbers conform to the
    * <a href='package-summary.html#deterministic-encoding' class='webpkilink'>Deterministic&nbsp;Encoding</a> rules.
    * <div>The {@link CBORDecoder#LENIENT_NUMBER_DECODING} option forces the decoder to
    * accept different representations of CBOR <code>int</code>, <code>bigint</code>,
    * and <code>float</code> items, only limited by RFC&nbsp;8949.</div></div>
    * <p>
    * Exceeding <code>maxInputLength</code> during decoding throws a {@link CBORException}.  It is
    * <i>recommendable</i> setting this as low as possible, since malformed
    * CBOR objects may request any amount of memory.
    * </p>
    * @param inputStream Stream holding CBOR data. 
    * @param options The decoder options.
    * @param maxInputLength Upper limit in bytes.
    * @throws CBORException
    * @see #getByteCount()
    */
    public CBORDecoder(InputStream inputStream, int options, int maxInputLength) {
        this.inputStream = inputStream;
        this.sequenceMode = (options & SEQUENCE_MODE) == SEQUENCE_MODE;
        this.strictMaps = (options & LENIENT_MAP_DECODING) != LENIENT_MAP_DECODING;
        this.strictNumbers = (options & LENIENT_NUMBER_DECODING) != LENIENT_NUMBER_DECODING;
        this.maxInputLength = maxInputLength;
    }
    
    private void eofError() {
        cborError(STDERR_CBOR_EOF);
    }

    private void unsupportedTag(int tag) {
        cborError(String.format(STDERR_UNSUPPORTED_TAG + "%02x", tag));
    }
    
    private void outOfLimitTest(int increment) {
        if ((byteCount += increment) > maxInputLength || byteCount < 0) {
            cborError(STDERR_READING_LIMIT);
        }
    }
    
    private int readByte() throws IOException {
        int i = inputStream.read();
        if (i < 0) {
            if (sequenceMode && atFirstByte) {
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

    private CBORFloat returnFloat(int tag, long bitFormat, double value) {
        CBORFloat cborFloat = new CBORFloat(value);
        if (strictNumbers &&
            (cborFloat.tag != tag || cborFloat.bitFormat != bitFormat)) {
            cborError(String.format(STDERR_NON_DETERMINISTIC_FLOAT + "%2x", tag));
        }
        return cborFloat;
    }

    private CBORObject returnNonFinite(long value) { 
        CBORNonFinite nonFinite = new CBORNonFinite(value);
        if (strictNumbers && nonFinite.value != value) {
            cborError(STDERR_NON_DETERMINISTIC_NON_FINITE + Long.toUnsignedString(value, 16));
        }
        return nonFinite;
    }

    private CBORObject getObject() throws IOException {
        int tag = readByte();

        // Begin with CBOR types that are uniquely defined by the tag byte.
        return switch (tag) {

            case MT_BIG_NEGATIVE, MT_BIG_UNSIGNED -> {
                byte[] byteArray = getObject().getBytes();
                BigInteger bigInteger = new BigInteger(1, byteArray);
                CBORBigInt cborBigInt = new CBORBigInt(tag == MT_BIG_UNSIGNED ? 
                                                                   bigInteger : bigInteger.not());
                if (strictNumbers) {
                    if (byteArray.length <= 8 || byteArray[0] == 0) {
                        cborError(STDERR_NON_DETERMINISTIC_BIGNUM);
                    } 
                } else {
                    // Normalization...
                    yield cborBigInt.clone();
                }
                yield cborBigInt;
            }

            case MT_FLOAT16 -> {
                long f16bin = getLongFromBytes(2);
                // Get the exponent.
                long exponent = f16bin & FLOAT16_POS_INFINITY;
                // Begin with the edge cases.
                if (exponent == FLOAT16_POS_INFINITY) {
                    // Non-finite numbers: Infinity, -Infinity, and NaN.
                    yield returnNonFinite(f16bin);
                }
                // It is a "regular" number.
                // Get the significand.
                long significand = f16bin & ((1L << FLOAT16_SIGNIFICAND_SIZE) - 1);
                if (exponent > 0) {
                    // Normal representation, add the implicit "1.".
                    significand += (1L << FLOAT16_SIGNIFICAND_SIZE);
                    // -1: Keep fractional point in line with subnormal numbers.
                    significand <<= ((exponent >> FLOAT16_SIGNIFICAND_SIZE) - 1);
                }
                // Divide with: (2 ^ (Exponent offset + Size of significand - 1)).
                double float64 = (double)significand / 
                        (1L << (FLOAT16_EXPONENT_BIAS + FLOAT16_SIGNIFICAND_SIZE - 1));
                yield returnFloat(tag, f16bin, f16bin >= FLOAT16_NEG_ZERO ? -float64 : float64);
            }

            case MT_FLOAT32 -> {
                long f32bin = getLongFromBytes(4);
                // Begin with the edge cases.
                if ((f32bin & FLOAT32_POS_INFINITY) == FLOAT32_POS_INFINITY) {
                    // Non-finite numbers: Infinity, -Infinity, and NaN.
                    yield returnNonFinite(f32bin);
                }
                // It is a "regular" number.
                yield returnFloat(tag, f32bin, Float.intBitsToFloat((int)f32bin));
            }

            case MT_FLOAT64 -> {
                long f64bin = getLongFromBytes(8);
                // Begin with the edge cases.
                if ((f64bin & FLOAT64_POS_INFINITY) == FLOAT64_POS_INFINITY) {
                    // Non-finite numbers: Infinity, -Infinity, and NaN.
                    yield returnNonFinite(f64bin);
                }
                // It is a "regular" number.
                yield returnFloat(tag, f64bin, Double.longBitsToDouble(f64bin));
            }

            case MT_NULL -> new CBORNull();
                
            case MT_TRUE, MT_FALSE -> new CBORBoolean(tag == MT_TRUE);

            default -> {
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
                    if (strictNumbers && ((n & mask) == 0 || (n > 0 && n < 24))) {
                        cborError(STDERR_NON_DETERMINISTIC_N);
                    }
                }
                // N successfully decoded, now switch on major type (upper three bits).
                yield switch (tag & 0xe0) {

                    case MT_SIMPLE -> new CBORSimple(checkLength(n));

                    case MT_TAG -> new CBORTag(n, getObject());

                    case MT_UNSIGNED -> new CBORInt(n, true);

                    // Only let two-complement integers use long.
                    case MT_NEGATIVE -> n < 0 ?
                        new CBORBigInt(NEGATIVE_HIGH_RANGE.add(BigInteger.valueOf(~n))) 
                                              :
                        new CBORInt(~n, false);
                    
                    case MT_BYTES -> new CBORBytes(readBytes(checkLength(n)));

                    case MT_STRING -> new CBORString(UTF8.decode(readBytes(checkLength(n))));

                    case MT_ARRAY -> {
                        CBORArray cborArray = new CBORArray();
                        for (int q = checkLength(n); --q >= 0; ) {
                            cborArray.add(getObject());
                        }
                        yield cborArray;
                    }

                    case MT_MAP -> {
                        CBORMap cborMap = new CBORMap().setSortingMode(strictMaps);
                        for (int q = checkLength(n); --q >= 0; ) {
                            cborMap.set(getObject(), getObject());
                        }
                        // Programmatically added elements will be sorted (by default). 
                        yield cborMap.setSortingMode(false);
                    }

                    default -> {
                        unsupportedTag(tag);
                        yield null;
                    }
                };
            }
        };
    }

    /**
     * Decode CBOR data with options.
     * <p>
     * Unsupported or malformed CBOR data cause a {@link CBORException} to be thrown.
     * </p>
     * @return {@link CBORObject} or <code>null</code> (for EOF sequences only).
     * @throws CBORException
     */
    public CBORObject decodeWithOptions() {        
        try {
            atFirstByte = true;
            CBORObject cborObject = getObject();
            if (sequenceMode) {
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
     * Decode CBOR data.
     * <p>
     * Unsupported or malformed CBOR data cause a {@link CBORException} to be thrown.
     * </p>
     * <p>
     * This conveniance method is identical to:
     * </p>
     * <div class='webpkifloat'>
     * <pre>  new CBORDecoder(new ByteArrayInputStream(cbor), 0, cbor.length)
     *      .decodeWithOptions();
     * </pre>
     * </div>
     * @param cbor CBOR binary data <i>holding exactly one CBOR object</i>.
     * @return {@link CBORObject}
     * @throws CBORException
     */
    public static CBORObject decode(byte[] cbor) {
        return new CBORDecoder(new ByteArrayInputStream(cbor), 0, cbor.length)
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

    static final String STDERR_NON_DETERMINISTIC_NON_FINITE =
            "Non-deterministic encoding of non-finite value: ";

    static final String STDERR_CBOR_EOF =
            "Malformed CBOR, trying to read past EOF";
    
    static final String STDERR_UNEXPECTED_DATA =
            "Unexpected data found after CBOR object";
    
    static final String STDERR_READING_LIMIT =
            "Reading past input limit";

}
