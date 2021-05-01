/*
 *  Copyright 2006-2021 WebPKI.org (http://webpki.org).
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
package org.webpki.sks.ws;


@SuppressWarnings("serial")
public class SKSException extends Exception {

    int error;

    public SKSException(org.webpki.sks.SKSException e) {
        super(e.getMessage());
        this.error = e.getError();
    }
    
    public SKSException(String message) {
        this(new org.webpki.sks.SKSException(message));
    }

    public SKSException(String message, int error) {
        this(new org.webpki.sks.SKSException(message, error));
    }

    public SKSException(Throwable e) {
        this(new org.webpki.sks.SKSException(e));
    }

    public int getError() {
        return error;
    }
}
