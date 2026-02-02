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

/**
 * CBOR internals.
 */
class CBORInternal {

    // Supported CBOR types.  All according to RFC 8949.
    static final int MT_UNSIGNED      = 0x00;
    static final int MT_NEGATIVE      = 0x20;
    static final int MT_BYTES         = 0x40;
    static final int MT_STRING        = 0x60;
    static final int MT_ARRAY         = 0x80;
    static final int MT_MAP           = 0xa0;
    static final int MT_TAG           = 0xc0;
    static final int MT_SIMPLE        = 0xe0;

    static final int TAG_BIG_UNSIGNED = 0xc2;
    static final int TAG_BIG_NEGATIVE = 0xc3;
    
    static final int SIMPLE_FALSE     = 0xf4;
    static final int SIMPLE_TRUE      = 0xf5;
    static final int SIMPLE_NULL      = 0xf6;
    static final int SIMPLE_FLOAT16   = 0xf9;
    static final int SIMPLE_FLOAT32   = 0xfa;
    static final int SIMPLE_FLOAT64   = 0xfb;

    // Floating-point constants.
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

    static final long FLOAT32_POS_INFINITY    = 0x000000007f800000L;
    static final long FLOAT32_NEG_ZERO        = 0x0000000080000000L;
     
    static final long FLOAT64_NOT_A_NUMBER    = 0x7ff8000000000000L;
    static final long FLOAT64_POS_INFINITY    = 0x7ff0000000000000L;
    static final long FLOAT64_NEG_INFINITY    = 0xfff0000000000000L;
    static final long FLOAT64_POS_ZERO        = 0x0000000000000000L;
    static final long FLOAT64_NEG_ZERO        = 0x8000000000000000L;

    static final long MASK_LOWER_32           = 0x00000000ffffffffL;
 
    // Integer specials.
    static final long UINT32_MASK             = 0xffffffff00000000L;
    static final long UINT16_MASK             = 0xffffffffffff0000L;
    static final long UINT8_MASK              = 0xffffffffffffff00L;

    // JavaScript Number.MAX_SAFE_INTEGER.
    static final long MAX_SAFE_JS_INTEGER     = 9007199254740991L;
    static final long MIN_SAFE_JS_INTEGER     = -MAX_SAFE_JS_INTEGER;

    // CBOR::Core time limits.
    static final long MAX_INSTANT_IN_MILLIS   = 253402300799000L; // 9999-12-31T23:59:59Z
    static final long MIN_INSTANT_IN_MILLIS   = -62167219200000L; // 0000-01-01T00:00:00Z;           
    
    static final int  MAX_ERROR_MESSAGE       = 100;

    static void cborError(String format, Object... args) {
        String error = String.format(format, args);
        if (error.length() > MAX_ERROR_MESSAGE) {
            error = error.substring(0, MAX_ERROR_MESSAGE - 3) + " ...";
        }
        throw new CBORException(error);
    }
}
