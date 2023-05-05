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
package org.webpki.keygen2;

import java.math.BigInteger;

import java.util.GregorianCalendar;

import org.webpki.crypto.CryptoException;
import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONObjectWriter;

import org.webpki.util.ISODateTime;

abstract class ServerEncoder extends JSONEncoder {

    abstract void writeServerRequest(JSONObjectWriter wr);

    final void bad(String message) {
        throw new CryptoException(message);
    }

    @Override
    public final String getContext() {
        return KeyGen2Constants.KEYGEN2_NS;
    }

    @Override
    final protected void writeJSONData(JSONObjectWriter wr) {
        writeServerRequest(wr);
    }

    void setOptionalString(JSONObjectWriter wr, String name, String value) {
        if (value != null) {
            wr.setString(name, value);
        }
    }

    void setOptionalStringArray(JSONObjectWriter wr, String name, String[] values) {
        if (values != null) {
            wr.setStringArray(name, values);
        }
    }

    void setOptionalBigInteger(JSONObjectWriter wr, String name, BigInteger value) {
        if (value != null) {
            wr.setBigInteger(name, value);
        }
    }

    void setOptionalBinary(JSONObjectWriter wr, String name, byte[] value) {
        if (value != null) {
            wr.setBinary(name, value);
        }
    }

    void setOptionalDateTime(JSONObjectWriter wr, 
                             String name, 
                             GregorianCalendar dateTime) {
        if (dateTime != null) {
            wr.setDateTime(name, dateTime, ISODateTime.UTC_NO_SUBSECONDS);  // Server UTC
        }
    }
}
