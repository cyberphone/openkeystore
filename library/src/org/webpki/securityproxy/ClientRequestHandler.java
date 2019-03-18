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

import java.io.IOException;

/**
 * Security proxy client request handler interface.
 * Must be implemented by a client (service).
 *
 * @see ProxyClient#initProxy(ClientRequestHandler, String, int, int, int, boolean)
 */
public interface ClientRequestHandler {
    /**
     * @param request_object the request
     * @return suitable HTTP return data to the external caller
     * @throws IOException If something unexpected happens...
     */
    public HTTPResponseWrapper handleHTTPResponseRequest(JavaRequestInterface request_object) throws IOException;

    /**
     * @param request_object the request
     * @return suitable Java return object to the external caller
     * @throws IOException If something unexpected happens...
     */
    public JavaResponseInterface handleJavaResponseRequest(JavaRequestInterface request_object) throws IOException;

    /**
     * Notify the proxy client user that proxy started or restarted.
     * This event can (for example) be used for performing initial uploads
     * ({@link JavaUploadInterface})
     * each time the proxy is started or restarts due to errors.
     *
     * @throws IOException If something unexpected happens...
     */
    public void handleInitialization() throws IOException;
}
