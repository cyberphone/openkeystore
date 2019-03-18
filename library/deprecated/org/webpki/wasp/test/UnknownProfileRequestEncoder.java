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
package org.webpki.wasp.test;

import java.io.IOException;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.XMLObjectWrapper;
import org.webpki.wasp.SignatureProfileEncoder;


public class UnknownProfileRequestEncoder extends XMLObjectWrapper implements SignatureProfileEncoder {

    private static final String UNSUP_XML_SCHEMA_NAMESPACE = "http://example.com/doesnotexist";

    private String prefix = "pr";  // Default: "pr:"

    public void init() throws IOException {
        throw new IOException("Must NOT be put in schema cache!");
    }


    public String namespace() {
        return UNSUP_XML_SCHEMA_NAMESPACE;
    }

    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }


    public String element() {
        return "Unknown.Profile.Request";
    }


    protected boolean hasQualifiedElements() {
        return true;
    }


    protected void toXML(DOMWriterHelper wr) throws IOException {
        wr.initializeRootObject(prefix);
        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes (which is all this profile got...)
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute("BlahBlah", "This profile is not for real!");
    }

    protected void fromXML(DOMReaderHelper helper) throws IOException {
        throw new IOException("Should NEVER be called");
    }


    public XMLObjectWrapper getXMLObjectWrapper() {
        return this;
    }

}
