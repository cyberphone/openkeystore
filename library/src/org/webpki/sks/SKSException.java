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
package org.webpki.sks;

import java.io.IOException;

@SuppressWarnings("serial")
public class SKSException extends IOException {
 
    /* Non-fatal error returned when there is something wrong with a
       supplied  PIN or PUK code.  See getKeyProtectionInfo */
    public static final int ERROR_AUTHORIZATION = 0x01;

    /* Operation is not allowed */
    public static final int ERROR_NOT_ALLOWED   = 0x02;

    /* No persistent storage available for the operation */
    public static final int ERROR_STORAGE       = 0x03;

    /* MAC does not match supplied data */
    public static final int ERROR_MAC           = 0x04;

    /* Various cryptographic errors */
    public static final int ERROR_CRYPTO        = 0x05;

    /* Provisioning session not found */
    public static final int ERROR_NO_SESSION    = 0x06;

    /* Key not found */
    public static final int ERROR_NO_KEY        = 0x07;

    /* Unknown or not fitting algorithm */
    public static final int ERROR_ALGORITHM     = 0x08;

    /* Invalid or unsupported option */
    public static final int ERROR_OPTION        = 0x09;

    /* Internal error */
    public static final int ERROR_INTERNAL      = 0x0A;

    /* External: Arbitrary error */
    public static final int ERROR_EXTERNAL      = 0x0B;

    /* External: User aborting PIN (or similar) error */
    public static final int ERROR_USER_ABORT    = 0x0C;

    /* External: Device not available  */
    public static final int ERROR_NOT_AVAILABLE = 0x0D;

    int error;

    public SKSException(String e, int error) {
        super(e);
        this.error = error;
    }

    public SKSException(Throwable t, int error) {
        super(t);
        this.error = error;
    }

    public SKSException(Throwable t) {
        super(t);
        this.error = ERROR_INTERNAL;
    }

    public SKSException(String e) {
        this(e, ERROR_INTERNAL);
    }

    public int getError() {
        return error;
    }
}
