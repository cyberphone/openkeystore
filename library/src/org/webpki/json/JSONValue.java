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
package org.webpki.json;

import java.io.Serializable;

/**
 * Local support class for holding individual values of JSON objects.
 */
class JSONValue implements Serializable {

    private static final long serialVersionUID = 1L;

    JSONTypes type;    // Number, String, etc.

    Object value;      // Holds either a String, JSONObject or Vector<JSONValue>

    boolean preSet;    // Number serialization optimizer

    boolean readFlag;  // For verifying that we dodn't forgot something

    JSONValue(JSONTypes type, Object value) {
        this.type = type;
        this.value = value;
    }
}
