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
package org.webpki.json;

import java.util.LinkedHashMap;
import java.util.ArrayList;

/**
 * Local support class for holding JSON objects.
 * Note that outer-level arrays are (&quot;hackishly&quot;) represented as a
 * JSON object having a single <b>null</b> property.
 */
class JSONObject {

    LinkedHashMap<String, JSONValue> properties = new LinkedHashMap<>();

    JSONObject() {
    }

    void setProperty(String name, JSONValue value) {
        if (properties.put(name, value) != null) {
            throw new JSONException("Duplicate property: " + name);
        }
    }

    static void checkObjectForUnread(JSONObject jsonObject) {
        for (String name : jsonObject.properties.keySet()) {
            JSONValue value = jsonObject.properties.get(name);
            if (!value.readFlag) {
                throw new JSONException("Property \"" + name + "\" was never read");
            }
            if (value.type == JSONTypes.OBJECT) {
                checkObjectForUnread((JSONObject) value.value);
            } else if (value.type == JSONTypes.ARRAY) {
                checkArrayForUnread(value, name);
            }
        }
    }

    @SuppressWarnings("unchecked")
    static void checkArrayForUnread(JSONValue array, String name) {
        for (JSONValue arrayElement : (ArrayList<JSONValue>) array.value) {
            if (arrayElement.type == JSONTypes.OBJECT) {
                checkObjectForUnread((JSONObject) arrayElement.value);
            } else if (arrayElement.type == JSONTypes.ARRAY) {
                checkArrayForUnread(arrayElement, name);
            } else if (!arrayElement.readFlag) {
                throw new JSONException("Value \"" + 
                                        (String) arrayElement.value + 
                                        "\" of array \"" + name + "\" was never read");
            }
        }
    }

    static void setObjectAsRead(JSONObject jsonObject) {
        for (String name : jsonObject.properties.keySet()) {
            JSONValue value = jsonObject.properties.get(name);
            value.readFlag = true;
            if (value.type == JSONTypes.OBJECT) {
                setObjectAsRead((JSONObject) value.value);
            } else if (value.type == JSONTypes.ARRAY) {
                setArrayAsRead(value);
            }
        }
    }

    @SuppressWarnings("unchecked")
    static void setArrayAsRead(JSONValue array) {
        for (JSONValue arrayElement : (ArrayList<JSONValue>) array.value) {
            if (arrayElement.type == JSONTypes.OBJECT) {
                setObjectAsRead((JSONObject) arrayElement.value);
            } else if (arrayElement.type == JSONTypes.ARRAY) {
                setArrayAsRead(arrayElement);
            } else {
                arrayElement.readFlag = true;
            }
        }
    }
}
