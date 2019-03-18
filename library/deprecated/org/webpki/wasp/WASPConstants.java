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

import org.webpki.crypto.KeyContainerTypes;


public interface WASPConstants {
    String WASP_NS = "http://xmlns.webpki.org/wasp/beta/core/20130604#";

    String WASP_SCHEMA_FILE = "wasp-core.xsd";

    String DOC_SIGN_CN_ALG = "http://xmlns.webpki.org/wasp/beta/core/20130604#cn";

    String[] TEXT_TYPES = new String[]{"text/plain",
            "text/html",
            "text/xml",
            "application/xhtml+xml",
            "application/xml",
            "text/css"};

    boolean[] MARKUP_TYPES = new boolean[]{false,
            true,
            true,
            true,
            true,
            false};


    String WEBAUTH_SCHEMA_FILE = "webauth.xsd";

    String WEBAUTH_NS = "http://xmlns.webpki.org/webauth/beta/20130604#";


    // Package only definitions

    String CERTIFICATE_FILTER_ELEM = "CertificateFilter";

    // Various global XML attributes

    String ID_ATTR = "ID";

    String SUBMIT_URL_ATTR = "SubmitURL";

    String REQUEST_URL_ATTR = "RequestURL";

    String ABORT_URL_ATTR = "AbortURL";

    String SERVER_TIME_ATTR = "ServerTime";

    String CLIENT_TIME_ATTR = "ClientTime";

    String LANGUAGES_ATTR = "Languages";

    String EXPIRES_ATTR = "Expires";

    String SIGNATURE_GUI_POLICY_ATTR = "SignatureGUIPolicy";

    String COPY_DATA_ATTR = "CopyData";

    String SERVER_CERT_FP_ATTR = "ServerCertificateFingerprint";

    String CLIENT_PLATFORM_FEATURES_ATTR = "ClientPlatformFeatures";

    String MIME_TYPE_ATTR = "MIMEType";

    String CONTENT_ID_ATTR = "ContentID";

    String DIGEST_ALG_ATTR = "DigestAlgorithm";

    String SIGNATURE_ALG_ATTR = "SignatureAlgorithm";

    String CN_ALG_ATTR = "CanonicalizationAlgorithm";

    String DOC_CN_ALG_ATTR = "DocumentCanonicalizationAlgorithm";

    String EXTENDED_CERT_PATH_ATTR = "ExtendedCertPath";

    String SIGNED_KEY_INFO_ATTR = "SignedKeyInfo";


    // Sub elements

    String MAIN_DOCUMENT_SUB_ELEM = "MainDocument";

    String EMBEDDED_OBJECT_SUB_ELEM = "EmbeddedObject";

    String BINARY_SUB_ELEM = "Binary";

    String TEXT_SUB_ELEM = "Text";

}
