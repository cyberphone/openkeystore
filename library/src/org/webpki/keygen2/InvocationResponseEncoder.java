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

import java.io.IOException;

import java.util.LinkedHashMap;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONObjectWriter;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class InvocationResponseEncoder extends JSONEncoder {

    private static final long serialVersionUID = 1L;

    String serverSessionId;

    byte[] nonce;  // For VMs

    LinkedHashMap<String, InvocationRequestDecoder.CAPABILITY> queriedCapabilities;

    LinkedHashMap<String, String[]> returnedValues = new LinkedHashMap<String, String[]>();

    class ImageAttributes {
        String mimeType;
        int width;
        int height;
    }

    LinkedHashMap<String, ImageAttributes> image_preferences = new LinkedHashMap<String, ImageAttributes>();

    void addCapability(String typeUri, InvocationRequestDecoder.CAPABILITY capability) throws IOException {
        InvocationRequestDecoder.CAPABILITY current = queriedCapabilities.get(typeUri);
        if (current == null || current != InvocationRequestDecoder.CAPABILITY.UNDEFINED) {
            KeyGen2Validator.bad("State error for URI: " + typeUri);
        }
        queriedCapabilities.put(typeUri, capability);
    }

    public InvocationResponseEncoder addImagePreference(String typeUri,
                                                        String mimeType,
                                                        int width,
                                                        int height) throws IOException {
        addCapability(typeUri, InvocationRequestDecoder.CAPABILITY.IMAGE_ATTRIBUTES);
        ImageAttributes im_pref = new ImageAttributes();
        im_pref.mimeType = mimeType;
        im_pref.width = width;
        im_pref.height = height;
        image_preferences.put(typeUri, im_pref);
        return this;
    }

    public InvocationResponseEncoder addSupportedFeature(String typeUri) throws IOException {
        addCapability(typeUri, InvocationRequestDecoder.CAPABILITY.URI_FEATURE);
        return this;
    }

    public InvocationResponseEncoder addClientValues(String typeUri, String[] values) throws IOException {
        addCapability(typeUri, InvocationRequestDecoder.CAPABILITY.VALUES);
        if (values.length == 0) {
            KeyGen2Validator.bad("Zero length array not allowed, URI: " + typeUri);
        }
        returnedValues.put(typeUri, values);
        return this;
    }

    public InvocationResponseEncoder(InvocationRequestDecoder decoder) {
        this.serverSessionId = decoder.serverSessionId;
        this.queriedCapabilities = decoder.queriedCapabilities;
    }

    public void setNonce(byte[] nonce) {
        this.nonce = nonce;
    }

    @Override
    @SuppressWarnings("fallthrough")
    protected void writeJSONData(JSONObjectWriter wr) throws IOException {
        ////////////////////////////////////////////////////////////////////////
        // Session properties
        ////////////////////////////////////////////////////////////////////////
        wr.setString(SERVER_SESSION_ID_JSON, serverSessionId);

        ////////////////////////////////////////////////////////////////////////
        // VM mandatory option
        ////////////////////////////////////////////////////////////////////////
        if (nonce != null) {
            wr.setBinary(NONCE_JSON, nonce);
        }

        ////////////////////////////////////////////////////////////////////////
        // Optional client capabilities
        ////////////////////////////////////////////////////////////////////////
        if (!queriedCapabilities.isEmpty()) {
            JSONArrayWriter aw = wr.setArray(CLIENT_CAPABILITIES_JSON);
            for (String uri : queriedCapabilities.keySet()) {
                JSONObjectWriter ow = aw.setObject().setString(TYPE_JSON, uri);
                boolean supported = false;
                switch (queriedCapabilities.get(uri)) {
                    case IMAGE_ATTRIBUTES:
                        ImageAttributes im_pref = image_preferences.get(uri);
                        ow.setObject(IMAGE_ATTRIBUTES_JSON)
                            .setString(MIME_TYPE_JSON, im_pref.mimeType)
                            .setInt(WIDTH_JSON, im_pref.width)
                            .setInt(HEIGHT_JSON, im_pref.height);
                        break;

                    case VALUES:
                        ow.setStringArray(VALUES_JSON, returnedValues.get(uri));
                        break;

                    case URI_FEATURE:
                        supported = true;
                    default:
                        ow.setBoolean(SUPPORTED_JSON, supported);
                }
            }
        }
    }

    @Override
    public String getQualifier() {
        return KeyGen2Messages.INVOCATION_RESPONSE.getName();
    }

    @Override
    public String getContext() {
        return KEYGEN2_NS;
    }
}
