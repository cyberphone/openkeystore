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

import java.security.cert.X509Certificate;

public class DeviceInfo {
    ///////////////////////////////////////////////////////////////////////////////////
    // "DeviceType" constants
    ///////////////////////////////////////////////////////////////////////////////////
    public static final byte LOCATION_EXTERNAL = 0x00;
    public static final byte LOCATION_EMBEDDED = 0x01;
    public static final byte LOCATION_SOCKETED = 0x02;
    public static final byte LOCATION_SIM      = 0x03;
    public static final byte LOCATION_MASK     = 0x03;

    public static final byte TYPE_SOFTWARE     = 0x00;
    public static final byte TYPE_HARDWARE     = 0x04;
    public static final byte TYPE_HSM          = 0x08;
    public static final byte TYPE_CPU          = 0x0C;
    public static final byte TYPE_MASK         = 0x0C;

    short apiLevel;

    public short getApiLevel() {
        return apiLevel;
    }

    private byte deviceType;

    public byte getDeviceType() {
        return deviceType;
    }

    String updateUrl;

    public String getUpdateUrl() {
        return updateUrl;
    }

    String vendorName;

    public String getVendorName() {
        return vendorName;
    }

    String vendorDescription;

    public String getVendorDescription() {
        return vendorDescription;
    }

    X509Certificate[] certificatePath;

    public X509Certificate[] getCertificatePath() {
        return certificatePath;
    }

    String[] supportedAlgorithms;

    public String[] getSupportedAlgorithms() {
        return supportedAlgorithms;
    }

    int cryptoDataSize;

    public int getCryptoDataSize() {
        return cryptoDataSize;
    }

    int extensionDataSize;

    public int getExtensionDataSize() {
        return extensionDataSize;
    }

    boolean devicePinSupport;

    public boolean getDevicePinSupport() {
        return devicePinSupport;
    }

    boolean biometricSupport;

    public boolean getBiometricSupport() {
        return biometricSupport;
    }

    public DeviceInfo(short apiLevel,
                      byte deviceType,
                      String updateUrl,  // May be null
                      String vendorName,
                      String vendorDescription,
                      X509Certificate[] certificatePath,
                      String[] supportedAlgorithms,
                      int cryptoDataSize,
                      int extensionDataSize,
                      boolean devicePinSupport,
                      boolean biometricSupport) {
        this.apiLevel = apiLevel;
        this.deviceType = deviceType;
        this.updateUrl = updateUrl;
        this.vendorName = vendorName;
        this.vendorDescription = vendorDescription;
        this.certificatePath = certificatePath;
        this.supportedAlgorithms = supportedAlgorithms;
        this.cryptoDataSize = cryptoDataSize;
        this.extensionDataSize = extensionDataSize;
        this.devicePinSupport = devicePinSupport;
        this.biometricSupport = biometricSupport;
    }
}
