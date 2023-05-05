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

import java.net.URI;
import java.net.URISyntaxException;

import java.util.GregorianCalendar;
import java.util.ArrayList;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONDecoder;
import org.webpki.json.JSONObjectReader;

import org.webpki.sks.SecureKeyStore;

import org.webpki.util.ISODateTime;

abstract class KeyGen2Validator extends JSONDecoder {

    static String validateID(String name, String value) {
        int l = value.length();
        if (l == 0 || l > SecureKeyStore.MAX_LENGTH_ID_TYPE) {
            bad("\"" + name + "\" length error: " + l);
        }
        while (l-- > 0) {
            char c = value.charAt(l);
            if (c < '!' || c > '~') {
                bad("\"" + name + "\" syntax error: '" + value + "'");
            }
        }
        return value;
    }

    static String getID(JSONObjectReader rd, String name) {
        return validateID(name, rd.getString(name));
    }

    static String getURL(JSONObjectReader rd, String name) {
        String url = getURI(rd, name);
        if (!url.matches("https?://.*")) {
            bad("Bad URL: " + url);
        }
        return url;
    }

    static private void validateURI(String uriString) {
        try {
            URI uri = new URI(uriString);
            if (!uri.isAbsolute()) {
                bad("Bad URI: " + uri);
            }
        } catch (URISyntaxException e) {
            throw new KeyGen2Exception(e);
        }
    }

    static String getURI(JSONObjectReader rd, String name) {
        String uri = rd.getString(name);
        validateURI(uri);
        return uri;
    }

    static short getPINLength(JSONObjectReader rd, String name) {
        int l = rd.getInt(name);
        if (l < 0 || l > SecureKeyStore.MAX_LENGTH_PIN_PUK) {
            bad("\"" + name + "\" value out of range: " + l);
        }
        return (short) l;
    }

    static void bad(String message) {
        throw new KeyGen2Exception(message);
    }

    static byte[] getMac(JSONObjectReader rd) {
        byte[] mac = rd.getBinary(KeyGen2Constants.MAC_JSON);
        if (mac.length != 32) {
            bad("\"" + KeyGen2Constants.MAC_JSON + "\" length error: " + mac.length);
        }
        return mac;
    }

    static byte[] getEncryptedKey(JSONObjectReader rd, String nameOfKey) {
        byte[] encryptedValue = rd.getBinary(nameOfKey);
        if (encryptedValue.length < SecureKeyStore.AES_CBC_PKCS5_PADDING ||
            encryptedValue.length > SecureKeyStore.MAX_LENGTH_PIN_PUK + SecureKeyStore.AES_CBC_PKCS5_PADDING) {
            bad("Encrypted protection for \"" + nameOfKey + "\" length error: " + encryptedValue.length);
        }
        return encryptedValue;
    }

    static short getAuthorizationRetryLimit(JSONObjectReader rd, int lowerLimit) {
        int retryLimit = rd.getInt(KeyGen2Constants.RETRY_LIMIT_JSON);
        if (retryLimit < lowerLimit || retryLimit > SecureKeyStore.MAX_RETRY_LIMIT) {
            bad("\"" + KeyGen2Constants.RETRY_LIMIT_JSON + "\" limit range error: " + retryLimit);
        }
        return (short) retryLimit;
    }

    static String[] getNonEmptyList(JSONObjectReader rd, String name) {
        String[] list = rd.getStringArray(name);
        if (list.length == 0) {
            bad("Empty list not allowed for: " + name);
        }
        return list;
    }

    static String[] getURIList(JSONObjectReader rd, String name) {
        String[] uris = getNonEmptyList(rd, name);
        for (String uri : uris) {
            validateURI(uri);
        }
        return uris;
    }

    static String[] getURIListConditional(JSONObjectReader rd, String name) {
        return rd.hasProperty(name) ? getURIList(rd, name) : null;
    }

    static BigInteger getBigIntegerConditional(JSONObjectReader rd, String name) {
        return rd.hasProperty(name) ? rd.getBigInteger(name) : null;
    }

    static GregorianCalendar getDateTimeConditional(JSONObjectReader rd, String name) {
        return rd.hasProperty(name) ? rd.getDateTime(name, ISODateTime.UTC_NO_SUBSECONDS) : null;
    }

    static ArrayList<JSONObjectReader> getObjectArrayConditional(JSONObjectReader rd, String name) {
        if (rd.hasProperty(name)) {
            return getObjectArray(rd, name);
        }
        return new ArrayList<>();
    }

    static ArrayList<JSONObjectReader> getObjectArray(JSONObjectReader rd, String name) {
        ArrayList<JSONObjectReader> result = new ArrayList<>();
        JSONArrayReader arr = rd.getArray(name);
        do {
            result.add(arr.getObject());
        }
        while (arr.hasMore());
        return result;
    }

    @Override
    final public String getContext() {
        return KeyGen2Constants.KEYGEN2_NS;
    }
}
