/*
 *  Copyright 2006-2020 WebPKI.org (http://webpki.org).
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
 * JSON output types.
 * It is used by {@link JSONObjectWriter}.
 */
public enum JSONOutputFormats {

    /**
     * As a string without whitespace where all items have a normalized form
     */
    NORMALIZED        (false, false, false, false),
    /**
     * Same as NORMALIZED but with properties sorted according to JCS
     */
    CANONICALIZED     (false, false, false, true),
    /**
     * Pretty-printed with JavaScript syntax
     */
    PRETTY_JS_NATIVE  (true,  true,  false, false),
    /**
     * Pretty-printed
     */
    PRETTY_PRINT      (true,  false, false, false),
    /**
     * Pretty-printed with HTML format
     */
    PRETTY_HTML       (true,  false, true,  false);

    boolean pretty;
    boolean javascript;
    boolean html;
    boolean canonicalized;

    JSONOutputFormats(boolean pretty, boolean javascript, boolean html,boolean canonicalized) {
        this.pretty = pretty;
        this.javascript = javascript;
        this.html = html;
        this.canonicalized = canonicalized;
    }
}
