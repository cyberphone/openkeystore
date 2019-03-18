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
 * Factory for returning internal security proxy errors.
 * Note: this is only for server-side errors.
 */
public abstract class ProxyServerErrorFactory {
    /**
     * This variable holds a message related to the error.
     * It is supposed to be merged with the custom container.
     * See source code of {@link SOAP12ServerError} for more details.
     */
    protected String message;

    public abstract byte[] getContent() throws IOException;

    public abstract String getMimeType();

    void setMessage(String message) {
        this.message = message;
    }

}
