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

import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;

import static org.webpki.wasp.WASPConstants.*;

/**
 * This is the base class which is extended by WASP "SignatureRequest" Encoder and Decoder
 */
abstract class SignatureRequest extends XMLObjectWrapper {

    SignatureRequest() {
    }

    static final String SIGNATURE_PROFILES_ELEM = "SignatureProfiles";

    static final String CF_SHA1_ATTR = "SHA1";
    static final String CF_ISSUER_ATTR = "Issuer";
    static final String CF_SUBJECT_ATTR = "Subject";
    static final String CF_EMAIL_ATTR = "Email";
    static final String CF_SERIAL_ATTR = "Serial";
    static final String CF_POLICY_ATTR = "Policy";
    static final String CF_CONTAINERS_ATTR = "Containers";
    static final String CF_KEY_USAGE_ATTR = "KeyUsage";
    static final String CF_EXT_KEY_USAGE_ATTR = "ExtKeyUsage";

    public void init() throws IOException {
        addWrapper(XMLSignatureWrapper.class);
        addSchema(WASP_SCHEMA_FILE);
    }


    protected boolean hasQualifiedElements() {
        return true;
    }


    public String namespace() {
        return WASP_NS;
    }


    public String element() {
        return "SignatureRequest";
    }


    protected void fromXML(DOMReaderHelper helper) throws IOException {
        throw new IOException("Should have been implemented in derived class");
    }


    protected void toXML(DOMWriterHelper helper) throws IOException {
        throw new IOException("Should have been implemented in derived class");
    }

}
