/*
 *  Copyright 2006-2021 WebPKI.org (http://webpki.org).
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
package org.webpki.cbor;

import java.io.IOException;

import java.util.EnumSet;
import java.util.GregorianCalendar;

import org.webpki.util.ArrayUtil;
import org.webpki.util.ISODateTime;

/**
 * Class for holding CBOR date-time objects (RFC 3339).
 */
public class CBORDateTime extends CBORObject {

    GregorianCalendar dateTime;
    String dateTimeString;  // For canonicalization

    static final byte[] DATE_TIME_TAG = {MT_DATE_TIME};

    /**
     * Create a CBOR <code>date-time</code> object.
     * 
     * @param dateTime Java format potentially including fractions of a second.
     * @param format Controls how it will be presented on the &quot;wire&quot;.
     */
    public CBORDateTime(GregorianCalendar dateTime, EnumSet<ISODateTime.DatePatterns> format) {
        this.dateTime = dateTime;
        this.dateTimeString = ISODateTime.formatDateTime(dateTime, format);
    }
    
    GregorianCalendar parseDateTime(EnumSet<ISODateTime.DatePatterns> constraints) 
            throws IOException {
        return ISODateTime.parseDateTime(dateTimeString, constraints);
    }

    /**
     * Create a CBOR <code>date-time</code> object.
     * 
     * @param dateTimeString ISO formatted string potentially including fractions of a second.
     */
    public CBORDateTime(String dateTimeString) throws IOException {
        this.dateTimeString = dateTimeString;
        this.dateTime = parseDateTime(ISODateTime.COMPLETE);
    }

    @Override
    CBORTypes internalGetType() {
        return CBORTypes.DATE_TIME;
    }

    @Override
    byte[] internalEncode() throws IOException {
        return ArrayUtil.add(DATE_TIME_TAG, new CBORTextString(dateTimeString).internalEncode());
    }

    @Override
    void internalToString(CBORObject.PrettyPrinter prettyPrinter) {
        prettyPrinter.appendText("0(\"").appendText(dateTimeString).appendText("\")");
    }
}
