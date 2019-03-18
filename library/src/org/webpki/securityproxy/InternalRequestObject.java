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

/**
 * Security proxy object containing a serialized request.
 * Internal usage only.
 */
class InternalRequestObject implements Serializable {
    private static final long serialVersionUID = 1L;

    JavaRequestInterface proxy_request;

    boolean java_flag;  // Java = true means return java object else http

    ////////////////////////////////////////////////////////
    // Due to the multi-channel proxy, calls need IDs
    ////////////////////////////////////////////////////////
    long caller_id;

    InternalRequestObject(JavaRequestInterface proxy_request, long caller_id, boolean java_flag) {
        this.proxy_request = proxy_request;
        this.caller_id = caller_id;
        this.java_flag = java_flag;
    }
}
