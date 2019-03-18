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
import java.math.*;

public class ASN1GeneralizedTime extends ASN1Time {

    private static final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
    private static final SimpleDateFormat encoderDateFormat = new SimpleDateFormat("yyyyMMddHHmmss");

    static {
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        encoderDateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    }

    public ASN1GeneralizedTime(Date utcTime) {
        super(GENERALIZEDTIME, utcTime);
    }

    ASN1GeneralizedTime(DerDecoder decoder) throws IOException {
        super(decoder);

        if (isPrimitive()) {
            if (decoder.length == -1) {
                throw new IOException("GeneralizedTime cannot have indefinite length(?).");
            }
            String date = new String(decoder.content());
            try {
                // iZ = index of timezone spec., iD = index of decimal point/comma
                int iZ = Math.max(date.indexOf('Z'), Math.max(date.indexOf('+'), date.indexOf('-'))),
                        iD = Math.max(date.indexOf('.'), date.indexOf(','));

                value = dateFormat.parse(date.substring(0, 14));

                if (iD != -1) {
                    // Add milliseconds (rounded if applicable)
                    value = new Date(value.getTime() +
                            new BigDecimal("0." +
                                    date.substring(15, Math.max(iZ, date.length())))
                                    .movePointRight(3).intValue());
                }

                if (iZ != -1 && date.charAt(iZ) != 'Z') {
                    // We have a time zone offset
                    value = new Date(value.getTime() -
                            (date.charAt(iZ) == '-' ? -1 : 1) *
                                    60 * 1000 * (60 * Integer.parseInt(date.substring(iZ, iZ + 2)) +
                                    ((date.length() > iZ + 2) ?
                                            Integer.parseInt(date.substring(iZ + 2, iZ + 4)) : 0)));
                }
            } catch (ParseException pe) {
                throw new IOException("Failed to decode Generalized Time " + date + ":\n" +
                        pe.getMessage());
            } catch (StringIndexOutOfBoundsException sioobe) {
                throw new IOException("Failed to decode Generalized Time " + date + ":\n" +
                        sioobe.getMessage());
            }
        } else {
            throw new IOException("Constructed GeneralizedTime not supported.");
        }
    }

    public boolean deepCompare(BaseASN1Object o) {
        return sameType(o) && ((ASN1GeneralizedTime) o).value.equals(value);
    }

    void toString(StringBuilder s, String prefix) {
        s.append(getByteNumber()).append(prefix).append("GeneralizedTime " + dateFormat.format(value));
    }

    String encodedForm() {
        return encoderDateFormat.format(value) + "Z";
    }
}
