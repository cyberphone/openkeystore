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
package org.webpki.sks.twolayer.se;

import java.security.cert.X509Certificate;

public class SEDeviceInfo {

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

    public SEDeviceInfo(short apiLevel,
                        byte deviceType,
                        String updateUrl,  // May be null
                        String vendorName,
                        String vendorDescription,
                        X509Certificate[] certificatePath,
                        String[] supportedAlgorithms,
                        int cryptoDataSize,
                        int extensionDataSize) {
        this.apiLevel = apiLevel;
        this.deviceType = deviceType;
        this.updateUrl = updateUrl;
        this.vendorName = vendorName;
        this.vendorDescription = vendorDescription;
        this.certificatePath = certificatePath;
        this.supportedAlgorithms = supportedAlgorithms;
        this.cryptoDataSize = cryptoDataSize;
        this.extensionDataSize = extensionDataSize;
    }
}
