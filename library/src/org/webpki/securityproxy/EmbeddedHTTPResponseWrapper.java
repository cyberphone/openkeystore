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
package org.webpki.securityproxy;

/**
 * Security proxy object containing a local service's HTTP response.
 * This version is supposed to be returned as a {@link JavaResponseInterface}
 *
 * @see ClientRequestHandler
 */
public class EmbeddedHTTPResponseWrapper extends HTTPResponseWrapper implements JavaResponseInterface {
    private static final long serialVersionUID = 1L;

    /**
     * For passing a HttpServletResponse "sendError"
     *
     * @param error_status  HTTP error code
     * @param error_message HTTP status message
     */
    public EmbeddedHTTPResponseWrapper(int error_status, String error_message) {
        super(error_status, error_message);
    }

    /**
     * For passing a HttpServletResponse "sendRedirect"
     *
     * @param redirect_url Arbitrary URL
     */
    public EmbeddedHTTPResponseWrapper(String redirect_url) {
        super(redirect_url);
    }

    /**
     * Normal HTTP return
     *
     * @param data      The HTTP body
     * @param mimeType The MIME type
     */
    public EmbeddedHTTPResponseWrapper(byte[] data, String mimeType) {
        super(data, mimeType);
    }
}
