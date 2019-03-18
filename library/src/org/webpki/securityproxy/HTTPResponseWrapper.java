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

import java.io.Serializable;

import java.util.LinkedHashMap;

import javax.servlet.http.HttpServletResponse;

/**
 * Security proxy object containing a local service's HTTP response.
 *
 * @see ClientRequestHandler
 */
public class HTTPResponseWrapper implements Serializable {
    private static final long serialVersionUID = 1L;

    byte[] data;

    String mimeType;

    String string_data;

    int error_status;

    LinkedHashMap<String, String> headers = new LinkedHashMap<String, String>();

    /**
     * For passing a HttpServletResponse "sendRedirect"
     *
     * @param redirect_url Arbitrary URL
     */
    public HTTPResponseWrapper(String redirect_url) {
        this.error_status = HttpServletResponse.SC_MOVED_TEMPORARILY;
        this.string_data = redirect_url;
    }

    /**
     * For passing a HttpServletResponse "sendError"
     *
     * @param error_status  HTTP error code
     * @param error_message HTTP status message
     */
    public HTTPResponseWrapper(int error_status, String error_message) {
        this.error_status = error_status;
        this.string_data = error_message;
    }

    /**
     * Normal HTTP return
     *
     * @param data      The HTTP body
     * @param mimeType The MIME type
     */
    public HTTPResponseWrapper(byte[] data, String mimeType) {
        this.data = data;
        this.mimeType = mimeType;
    }

    /**
     * Adds a header to the HTTP response
     *
     * @param name  Name of HTTP header
     * @param value Value of HTTP Header
     */
    public void addHeader(String name, String value) {
        headers.put(name, value);
    }

    /**
     * Checks if the returned object contains an HTTP error.
     *
     * @return True if the object contains an HTTP error
     */
    public boolean isError() {
        return error_status != 0;
    }
}
