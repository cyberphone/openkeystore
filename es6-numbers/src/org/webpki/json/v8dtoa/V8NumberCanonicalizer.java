/* -*- Mode: java; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.webpki.json.v8dtoa;


/**
 * This is the class that implements the runtime.
 *
 * @author Norris Boyd
 */

public class V8NumberCanonicalizer {

    /**
     * No instances should be created.
     */
    private V8NumberCanonicalizer() {
    }


 
    // Can not use Double.NaN defined as 0.0d / 0.0 as under the Microsoft VM,
    // versions 2.01 and 3.0P1, that causes some uses (returns at least) of
    // Double.NaN to be converted to 1.0.
    // So we use ScriptRuntime.NaN instead of Double.NaN.
    public static final double
        NaN = Double.longBitsToDouble(0x7ff8000000000000L);

    // A similar problem exists for negative zero.
    public static final double
        negativeZero = Double.longBitsToDouble(0x8000000000000000L);

    public static final Double NaNobj = new Double(NaN);


    public static String numberToString(double d) {

        // 1. Check for JSON compatibility.
        if (Double.isNaN(d) || Double.isInfinite(d)) {
            throw new IllegalArgumentException("NaN/Infinity are not permitted in JSON");
        }

        if (d == 0.0)
            return "0";

        // V8 FastDtoa can't convert all numbers, so try it first but
        // fall back to old DToA in case it fails
        String result = FastDtoa.numberToString(d);
        if (result != null) {
            StringBuilder buffer = new StringBuilder();
            DToA.JS_dtostr(buffer, DToA.DTOSTR_STANDARD, 0, d);
            String dtoa = buffer.toString();
            if (!result.equals(dtoa)) {
                System.out.println("V8=" + result + "\n" + "DT=" + dtoa);
            }
            return result;
        }
        StringBuilder buffer = new StringBuilder();
        DToA.JS_dtostr(buffer, DToA.DTOSTR_STANDARD, 0, d);
        return buffer.toString();
    }

}
