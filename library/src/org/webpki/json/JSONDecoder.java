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

import java.io.IOException;
import java.io.Serializable;

/**
 * Base class for java classes which can be created from specific JSON object types.
 * <p>
 * It is designed to use {@link JSONDecoderCache} to get automatic instantiation.
 */
public abstract class JSONDecoder implements Serializable {

    private static final long serialVersionUID = 1L;

    JSONObject root;  // Of parsed document

    /**
     * INTERNAL USE ONLY.
     *
     * @param rd A JSON reader
     * @throws IOException For any kind of error...
     */
    protected abstract void readJSONData(JSONObjectReader rd) throws IOException;

    /**
     * Emulation of XML namespace
     *
     * @return The context name
     */
    public abstract String getContext();

    /**
     * Optional type indicator for JSON objects belonging to the same <code>@context</code>.
     *
     * @return The qualifier name
     */
    public String getQualifier() {
        return null;
    }

    public JSONObjectWriter getWriter() throws IOException {
        return new JSONObjectWriter(root);
    }
}
