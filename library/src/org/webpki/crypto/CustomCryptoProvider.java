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
package org.webpki.crypto;

import java.security.Provider;
import java.security.Security;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Bouncycastle loader
 */
public class CustomCryptoProvider {

    private static Logger logger = Logger.getLogger(CustomCryptoProvider.class.getCanonicalName());

    private CustomCryptoProvider() {} // No instantiation

    private static boolean loadBouncyCastle(boolean insertFirst, boolean require) {
        return false;
    }

    public static boolean conditionalLoad(boolean insertFirst) {
        return loadBouncyCastle(insertFirst, false);
    }

    public static void forcedLoad(boolean insertFirst) {
        loadBouncyCastle(insertFirst, true);
    }
}
