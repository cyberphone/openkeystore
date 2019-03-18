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
 * Security proxy object containing a serialized HTTP response.
 * Internal use only.  Data is tunneled through the proxy out to the requester.
 */
class InternalResponseObject extends InternalClientObject {
    private static final long serialVersionUID = 1L;

    HTTPResponseWrapper response_data;  //  May contain a wrapped JavaResponseObject as well

    boolean return_immediately;

    ////////////////////////////////////////////////////////
    // Due to the multi-channel proxy, calls need IDs
    ////////////////////////////////////////////////////////
    long caller_id;

    InternalResponseObject(HTTPResponseWrapper response_data, long caller_id, String client_id, boolean return_immediately) {
        super(client_id);
        this.caller_id = caller_id;
        this.response_data = response_data;
        this.return_immediately = return_immediately;
    }
}
