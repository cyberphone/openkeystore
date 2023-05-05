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

/**
 * Basic JSON types read by the parser.
 */
public enum JSONTypes {

    NULL    (false),
    BOOLEAN (false),
    NUMBER  (false),
    STRING  (false),
    ARRAY   (true),
    OBJECT  (true);

    boolean complex;

    JSONTypes(boolean complex) {
        this.complex = complex;
    }

    static void compatibilityTest(JSONTypes expectedType, JSONValue value) {
        if (expectedType != value.type) {
            throw new JSONException("Incompatible types, expected: " + 
                                    expectedType + " actual: " + value.type);
        }
    }
}
