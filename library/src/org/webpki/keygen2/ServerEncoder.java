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
package org.webpki.keygen2;

import java.io.IOException;

import java.math.BigInteger;

import java.util.GregorianCalendar;

import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONObjectWriter;
import org.webpki.util.ISODateTime;

abstract class ServerEncoder extends JSONEncoder {

    private static final long serialVersionUID = 1L;

    abstract void writeServerRequest(JSONObjectWriter wr) throws IOException;

    final void bad(String message) throws IOException {
        throw new IOException(message);
    }

    @Override
    public final String getContext() {
        return KeyGen2Constants.KEYGEN2_NS;
    }

    @Override
    final protected void writeJSONData(JSONObjectWriter wr) throws IOException {
        writeServerRequest(wr);
    }

    void setOptionalString(JSONObjectWriter wr, String name, String value) throws IOException {
        if (value != null) {
            wr.setString(name, value);
        }
    }

    void setOptionalStringArray(JSONObjectWriter wr, String name, String[] values) throws IOException {
        if (values != null) {
            wr.setStringArray(name, values);
        }
    }

    void setOptionalBigInteger(JSONObjectWriter wr, String name, BigInteger value) throws IOException {
        if (value != null) {
            wr.setBigInteger(name, value);
        }
    }

    void setOptionalBinary(JSONObjectWriter wr, String name, byte[] value) throws IOException {
        if (value != null) {
            wr.setBinary(name, value);
        }
    }

    void setOptionalDateTime(JSONObjectWriter wr, String name, GregorianCalendar dateTime) throws IOException {
        if (dateTime != null) {
            wr.setDateTime(name, dateTime, ISODateTime.UTC_NO_SUBSECONDS);  // Server UTC
        }
    }
}
