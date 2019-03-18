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
 * Security proxy object containing an upload operation.
 * Only for proxy-internal use.
 */
class InternalUploadObject extends InternalClientObject {
    private static final long serialVersionUID = 1L;

    private byte[] data;

    JavaUploadInterface getPayload(ServerUploadHandler handler) throws IOException, ClassNotFoundException {
        return (JavaUploadInterface) InternalObjectStream.readObject(data, handler);
    }

    InternalUploadObject(String client_id, JavaUploadInterface payload) throws IOException {
        super(client_id);
        data = InternalObjectStream.writeObject(payload);
    }
}
