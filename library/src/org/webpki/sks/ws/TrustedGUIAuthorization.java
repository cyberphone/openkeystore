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
package org.webpki.sks.ws;

import org.webpki.sks.AppUsage;
import org.webpki.sks.Grouping;
import org.webpki.sks.PassphraseFormat;
import org.webpki.sks.SKSException;

public interface TrustedGUIAuthorization {
    byte[] restoreTrustedAuthorization(byte[] value) throws SKSException;

    byte[] getTrustedAuthorization(PassphraseFormat format,
                                   Grouping grouping,
                                   AppUsage appUsage,
                                   String friendlyName) throws SKSException;

    String getImplementation();
}
