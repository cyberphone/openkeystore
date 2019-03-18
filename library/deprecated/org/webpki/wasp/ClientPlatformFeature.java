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

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.XMLCookie;

/**
 * Implements the WASP/WebAuth "ClientPlatformFeature" XML object
 */
public class ClientPlatformFeature {
    public ClientPlatformFeature(String featureUri, XMLCookie xml_cookie) {
        this.featureUri = featureUri;
        this.xml_cookie = xml_cookie;
    }

    String featureUri;

    private XMLCookie xml_cookie;

    public static final String CLIENT_PLATFORM_FEATURE_ELEM = "ClientPlatformFeature";

    private static final String URI_ATTR = "URI";

    public String getFeatureURI() {
        return featureUri;
    }

    public XMLCookie getXMLCookie() throws IOException {
        return xml_cookie;
    }

    static ClientPlatformFeature read(DOMReaderHelper rd) throws IOException {
        rd.getNext(CLIENT_PLATFORM_FEATURE_ELEM);
        String uri = rd.getAttributeHelper().getString(URI_ATTR);
        rd.getChild();
        XMLCookie xml_cookie = rd.getXMLCookie();
        rd.getParent();
        return new ClientPlatformFeature(uri, xml_cookie);
    }

    public void write(DOMWriterHelper wr) throws IOException {
        wr.addChildElement(CLIENT_PLATFORM_FEATURE_ELEM);
        wr.setStringAttribute(URI_ATTR, featureUri);
        wr.addXMLCookie(xml_cookie);
        wr.getParent();
    }
}
