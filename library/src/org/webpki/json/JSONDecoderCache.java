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
package org.webpki.json;

import java.lang.reflect.InvocationTargetException;

import java.util.Hashtable;

/**
 * Stores {@link JSONDecoder} classes for automatic instantiation during parsing.
 * This is (sort of) an emulation of XML schema caches.
 * <p>
 * The cache system assumes that JSON documents follow a strict convention:<br>
 * &nbsp;<br><code>
 * &nbsp;&nbsp;{<br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;@context&quot;:&nbsp;&quot;</code><i>Message Context</i><code>&quot;<br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;@qualifier&quot;:&nbsp;&quot;</code><i>Message Type Qualifier</i><code>&quot;<br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;.<br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;.&nbsp;&nbsp;&nbsp;</code><i>Arbitrary JSON Payload</i><code><br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;.<br>
 * &nbsp;&nbsp;}</code><p>
 * Note: <code>@qualifier</code> is only required if multiple objects share the same <code>@context</code>.<p>
 * A restriction imposed by this particular JSON processing model is that all properties must by default be read.
 */
public class JSONDecoderCache {

    /**
     * Emulation of XML namespace
     */
    public static final String CONTEXT_JSON     = "@context";

    /**
     * Emulation of XML top-level element. Optional
     */
    public static final String QUALIFIER_JSON   = "@qualifier";

    static final char CONTEXT_QUALIFIER_DIVIDER = '$';

    boolean checkForUnread = true;

    Hashtable<String, Class<? extends JSONDecoder>> classMap = new Hashtable<>();

    public JSONDecoder parse(JSONObjectReader reader) {
        String objectTypeIdentifier = reader.getString(CONTEXT_JSON);
        if (reader.hasProperty(QUALIFIER_JSON)) {
            objectTypeIdentifier += CONTEXT_QUALIFIER_DIVIDER + reader.getString(QUALIFIER_JSON);
        }
        Class<? extends JSONDecoder> decoderClass = classMap.get(objectTypeIdentifier);
        if (decoderClass == null) {
            throw new JSONException("Unknown JSONDecoder type: " + objectTypeIdentifier);
        }
        try {
            JSONDecoder decoder = decoderClass.getDeclaredConstructor().newInstance();
            decoder.root = reader.root;
            decoder.readJSONData(reader);
            if (checkForUnread) {
                reader.checkForUnread();
            }
            return decoder;
        } catch (InstantiationException | InvocationTargetException | 
                 NoSuchMethodException | IllegalAccessException e) {
            throw new JSONException (e);
        }
    }

    public JSONDecoder parse(byte[] jsonUtf8) {
        return parse(JSONParser.parse(jsonUtf8));
    }

    public void addToCache(Class<? extends JSONDecoder> jsonDecoder) {
        try {
            JSONDecoder decoder = jsonDecoder.getDeclaredConstructor().newInstance();
            String objectTypeIdentifier = decoder.getContext();
            if (decoder.getQualifier() != null) {
                objectTypeIdentifier += CONTEXT_QUALIFIER_DIVIDER + decoder.getQualifier();
            }
            if (classMap.put(objectTypeIdentifier, decoder.getClass()) != null) {
                throw new JSONException("JSON document type already defined: " + objectTypeIdentifier);
            }
        } catch (InstantiationException | InvocationTargetException | 
                 NoSuchMethodException | IllegalAccessException e) {
            throw new JSONException (e);
        }

    }

    public void addToCache(String jsonDecoderPath) {
        try {
            addToCache(Class.forName(jsonDecoderPath).asSubclass(JSONDecoder.class));
        } catch (ClassNotFoundException e) {
            throw new JSONException(e);
        }
    }

    public void setCheckForUnreadProperties(boolean flag) {
        checkForUnread = flag;
    }
}
