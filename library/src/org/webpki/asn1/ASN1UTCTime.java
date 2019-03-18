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
import java.util.*;
import java.text.*;

public class ASN1UTCTime extends ASN1Time {
    private static final SimpleDateFormat dateFormat = new SimpleDateFormat("yyMMddHHmmss");

    static {
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    }

    private static Date parseUTCTime(String utcTime)
            throws ParseException {
        try {
            Date r;

            // iZ = index of timezone spec., iD = index of decimal point/comma
            int iZ = Math.max(utcTime.indexOf('Z'), Math.max(utcTime.indexOf('+'), utcTime.indexOf('-')));

            if (iZ == 10) {
                // Compensate for missing seconds
                r = dateFormat.parse(utcTime.substring(0, 10) + "00");
            } else {
                r = dateFormat.parse(utcTime.substring(0, 12));
            }

            if (iZ != -1 && utcTime.charAt(iZ) != 'Z') {
                // We have a time zone offset
                r = new Date(r.getTime() -
                        (utcTime.charAt(iZ) == '-' ? -1 : 1) *
                                60 * 1000 * (60 * Integer.parseInt(utcTime.substring(iZ, iZ + 2)) +
                                ((utcTime.length() > iZ + 2) ?
                                        Integer.parseInt(utcTime.substring(iZ + 2, iZ + 4)) : 0)));
            }

            return r;
        } catch (StringIndexOutOfBoundsException sioobe) {
            throw new ParseException("Failed to parse UTC Time " + utcTime + ":\n" +
                    sioobe.getMessage(), -1);
        }
    }

    public ASN1UTCTime(Date utcTime) {
        super(UTCTIME, utcTime);
    }

    public ASN1UTCTime(String utcTime) throws ParseException {
        this(parseUTCTime(utcTime));
    }

    ASN1UTCTime(DerDecoder decoder) throws IOException {
        super(decoder);

        if (isPrimitive()) {
            if (decoder.length == -1) {
                throw new IOException("UTCTime cannot have indefinite length(?).");
            }

            String utcTime = new String(decoder.content());

            try {
                value = parseUTCTime(utcTime);
            } catch (ParseException pe) {
                throw new IOException("Failed to decode UTC Time " + utcTime + ":\n" +
                        pe.getMessage());
            }
        } else {
            throw new IOException("Constructed UTCTime not supported.");
        }
    }

    public boolean deepCompare(BaseASN1Object o) {
        return sameType(o) && ((ASN1UTCTime) o).value.equals(value);
    }

    void toString(StringBuilder s, String prefix) {
        s.append(getByteNumber()).append(prefix + "UTCTime ").append(dateFormat.format(value));
    }

    String encodedForm() {
        return dateFormat.format(value) + "Z";
    }
}
