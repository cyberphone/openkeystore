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

import java.security.cert.X509Certificate;

import org.webpki.sks.DeviceInfo;
import org.webpki.sks.SKSException;

public class WSDeviceInfo extends DeviceInfo {
    /**
     * Holds an optional system-dependent string telling which logical
     * or physical port the SKS is connected to.  This information is
     * not gathered from the SKS device itself, but from the calling
     * environment.  Suitable strings include "USB:4", "COM3", "TCP:192.168.0.45",
     * "/dev/term3", "PCI:2", "Embedded", "SIM", "http://net-hsm/sks", etc.
     */
    String connectionPort;

    public WSDeviceInfo(short apiLevel,
                        byte deviceType,
                        String updateUrl,
                        String vendorName,
                        String vendorDescription,
                        X509Certificate[] certificatePath,
                        String[] supportedAlgorithms,
                        int cryptoDataSize, int
                                extensionDataSize,
                        boolean devicePinSupport,
                        boolean biometricSupport,
                        String connectionPort) {
        super(apiLevel,
                deviceType,
                updateUrl,
                vendorName,
                vendorDescription,
                certificatePath,
                supportedAlgorithms,
                cryptoDataSize,
                extensionDataSize,
                devicePinSupport,
                biometricSupport);
        connectionPort = this.connectionPort;
    }

    public String getConnectionPort() {
        return connectionPort;
    }
}
