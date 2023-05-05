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
package org.webpki.webauth;

import java.math.BigInteger;

import java.net.URI;

import java.net.URISyntaxException;

import java.util.ArrayList;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONDecoder;
import org.webpki.json.JSONException;
import org.webpki.json.JSONObjectReader;

abstract class InputValidator extends JSONDecoder {

    static String getID(JSONObjectReader rd, String name) {
        return rd.getString(name);
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
            throw new JSONException(e);
        }
    }

    static String getURI(JSONObjectReader rd, String name) {
        String uri = rd.getString(name);
        validateURI(uri);
        return uri;
    }

    static void bad(String message) {
        throw new JSONException(message);
    }

    static String[] getNonEmptyList(JSONObjectReader rd, String name) {
        String[] list = rd.getStringArray(name);
        if (list.length == 0) {
            bad("Empty list not allowed: " + name);
        }
        return list;
    }

    static String[] getListConditional(JSONObjectReader rd, String name) {
        return rd.hasProperty(name) ? getNonEmptyList(rd, name) : null;
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
        } while (arr.hasMore());
        return result;
    }

    @Override
    final public String getContext() {
        return WebAuthConstants.WEBAUTH_NS;
    }
}
