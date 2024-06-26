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
package org.webpki.securityproxy;

/**
 * Security proxy upload event handler.
 * Implement in proxy-using servlet.
 *
 * @see ProxyServer#addUploadEventHandler(ServerUploadHandler)
 * @see ProxyServer#deleteUploadEventHandler(ServerUploadHandler)
 */
public interface ServerUploadHandler {
    /**
     * @param upload_object the uploaded data
     */
    public void handleUploadedData(JavaUploadInterface upload_object);
}
