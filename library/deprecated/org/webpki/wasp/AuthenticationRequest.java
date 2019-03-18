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
package org.webpki.wasp;

import java.io.IOException;

import java.util.Vector;

import org.webpki.crypto.CertificateFilter;

import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;

import static org.webpki.wasp.WASPConstants.*;

/**
 * This is the base class which is extended by Web Authentication
 * "AuthenticationRequest" Encoder and Decoder
 */
abstract class AuthenticationRequest extends XMLObjectWrapper {
    String id;

    String submitUrl;

    String abortUrl;                                                          // Optional

    String[] languages;                                                         // Optional

    int expires;

    Vector<AuthenticationProfile> authentication_profiles = new Vector<AuthenticationProfile>();

    Vector<CertificateFilter> certificateFilters = new Vector<CertificateFilter>();

    Vector<String> requested_client_platform_features = new Vector<String>();

    AuthenticationRequest() {
    }

    static final String AUTHENTICATION_PROFILE_ELEM = "AuthenticationProfile";

    public void init() throws IOException {
        addWrapper(XMLSignatureWrapper.class);
        addSchema(WEBAUTH_SCHEMA_FILE);
    }


    protected boolean hasQualifiedElements() {
        return true;
    }


    public String namespace() {
        return WEBAUTH_NS;
    }


    public String element() {
        return "AuthenticationRequest";
    }


    protected void fromXML(DOMReaderHelper helper) throws IOException {
        throw new IOException("Should have been implemented in derived class");
    }


    protected void toXML(DOMWriterHelper helper) throws IOException {
        throw new IOException("Should have been implemented in derived class");
    }
}
