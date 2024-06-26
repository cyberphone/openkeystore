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
package org.webpki.wasp.prof.xds;

public interface XDSProfileConstants {
    String XML_SCHEMA_NAMESPACE = "http://xmlns.webpki.org/wasp/1.0/prof/xds#";

    String XML_SCHEMA_FILE = "wasp-prof-xmldsig.xsd";

    String REQUEST_ELEM = "ProfileData";

    String RESPONSE_ELEM = "SignedData";

    String UNREFERENCED_ATTACHMENTS_ATTR = "UnreferencedAttachments";
}
