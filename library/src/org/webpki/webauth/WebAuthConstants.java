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
package org.webpki.webauth;


public interface WebAuthConstants {

    String WEBAUTH_NS                      = "http://xmlns.webpki.org/webauth/beta/20151101";
    
    String AUTHENTICATION_REQUEST_MSG      = "AuthenticationRequest";

    String AUTHENTICATION_RESPONSE_MS      = "AuthenticationResponse";

    int MAX_ID_LENGTH                      = 32;


    // JSON properties

    String ABORT_URL_JSON                  = "abortUrl";

    String CERTIFICATE_FILTERS_JSON        = "certificateFilters";

    String CLIENT_FEATURES_JSON            = "clientFeatures";

    String CLIENT_TIME_JSON                = "clientTime";

    String EXPIRES_JSON                    = "expires";

    String EXTENDED_CERT_PATH_JSON         = "extendedCertPath";

    String ID_JSON                         = "id";

    String PREFERRED_LANGUAGES_JSON        = "preferredLanguages";

    String REQUESTED_CLIENT_FEATURES_JSON  = "requestedClientFeatures";

    String REQUEST_URL_JSON                = "requestUrl";

    String SERVER_CERT_FP_JSON             = "serverCertificateFingerPrint";

    String SERVER_TIME_JSON                = "serverTime";

    String SIGNATURE_ALGORITHMS_JSON       = "signatureAlgorithms";
    
    String SUBMIT_URL_JSON                 = "submitUrl";

    String TYPE_JSON                       = "type";

    String VALUES_JSON                     = "values";
}
