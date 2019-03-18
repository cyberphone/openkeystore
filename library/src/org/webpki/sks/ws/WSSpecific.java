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

import org.webpki.sks.SKSException;

public interface WSSpecific {
    /**
     * Non-SKS method for SKS devices
     *
     * @return devices ids
     */
    String[] listDevices() throws SKSException;

    /**
     * Non-SKS method for getting WS interface version
     *
     * @return version string
     */
    String getVersion();

    /**
     * Non-SKS method for logging data.
     * Transfers log data from SKS applications to the WS log
     *
     * @param event
     */
    void logEvent(String event);

    /**
     * Setup WS driver property
     */
    boolean setTrustedGUIAuthorizationProvider(TrustedGUIAuthorization tga_provider);

    /**
     * Setup WS device property
     */
    void setDeviceID(String deviceId);
}
