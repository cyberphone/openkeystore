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

/**
 * Base class for java classes which are used for creating specific JSON object types.
 */
public abstract class JSONEncoder {

    JSONObject root;  // Of written document

    /**
     * INTERNAL USE ONLY.
     */
    protected JSONEncoder() {}

    /**
     * INTERNAL USE ONLY.
     *
     * @param wr A JSON writer
     */
    protected abstract void writeJSONData(JSONObjectWriter wr);

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

    /**
     * @param outputFormat The wanted formatting
     * @return Document in JSON [binary] format
     */
    public byte[] serializeJSONDocument(JSONOutputFormats outputFormat) {
        JSONObjectWriter wr = new JSONObjectWriter();
        root = wr.root;
        wr.setString(JSONDecoderCache.CONTEXT_JSON, getContext());
        if (getQualifier() != null) {
            wr.setString(JSONDecoderCache.QUALIFIER_JSON, getQualifier());
        }
        writeJSONData(wr);
        return wr.serializeToBytes(outputFormat);
    }
}
