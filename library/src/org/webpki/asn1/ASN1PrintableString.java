/*
 *  Copyright 2006-2018 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.asn1;

import java.io.IOException;
import java.util.BitSet;

import org.webpki.util.StringUtil;

public class ASN1PrintableString extends ASN1String {
    public ASN1PrintableString(String value) {
        super(PRINTABLESTRING, value);
        StringUtil.checkAllowedChars(value, allowedChars);
    }

    ASN1PrintableString(DerDecoder decoder) throws IOException {
        super(decoder);
    }

    private static BitSet allowedChars;

    static {
        allowedChars = StringUtil.charSet(" '+,-./:=?()");
        for (char c = 'a'; c <= 'z'; c++) {
            allowedChars.set(c);
        }
        for (char c = 'A'; c <= 'Z'; c++) {
            allowedChars.set(c);
        }
        for (char c = '0'; c <= '9'; c++) {
            allowedChars.set(c);
        }
    }

    /*
     * Checks if a string contains only characters allowable in a PrintableString.
     * <p>The folliwing characters are allowed (taken from section 3.3.3 of RFC1148)
     * <pre>  printablestring  = *( ps-char )
     *   ps-restricted-char = 1DIGIT /  1ALPHA / " " / "'" / "+"
     *                    / "," / "-" / "." / "/" / ":" / "=" / "?"
     *   ps-delim         = "(" / ")"
     *   ps-char          = ps-delim / ps-restricted-char</pre>
     */
    public static boolean isPrintableString(String s) {
        return StringUtil.hasOnlyLegalChars(s, allowedChars);
    }

    void toString(StringBuilder s, String prefix) {
        s.append(getByteNumber()).append(prefix).append("PrintableString '").append(value()).append('\'');
    }
}
