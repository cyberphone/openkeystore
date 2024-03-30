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
package org.webpki.sks;

import java.security.cert.X509Certificate;

import java.util.LinkedHashSet;


public class KeyAttributes {

    short symmetricKeyLength;

    X509Certificate[] certificatePath;

    byte appUsage;

    String friendlyName;

    LinkedHashSet<String> endorsedAlgorithms;

    LinkedHashSet<String> extensionTypes;


    static LinkedHashSet<String> fillSet(String[] stringArray) {
        LinkedHashSet<String> hashSet = new LinkedHashSet<>();
        for(String string : stringArray) {
            hashSet.add(string);
        }
        return hashSet;
    }

    public boolean isSymmetricKey() {
        return symmetricKeyLength > 0;
    }

    public short getSymmetricKeyLength() {
        return symmetricKeyLength;
    }

    public X509Certificate[] getCertificatePath() {
        return certificatePath;
    }

    public AppUsage getAppUsage() throws SKSException {
        for (AppUsage au : AppUsage.values()) {
            if (au.getSksValue() == appUsage) {
                return au;
            }
        }
        throw new SKSException("Internal AppUsage error");
    }

    public String getFriendlyName() {
        return friendlyName;
    }

    public LinkedHashSet<String> getEndorsedAlgorithms() {
        return extensionTypes;
    }

    public LinkedHashSet<String> getExtensionTypes() {
        return extensionTypes;
    }

    public KeyAttributes(short symmetricKeyLength,
                         X509Certificate[] certificatePath,
                         byte appUsage,
                         String friendlyName,
                         String[] endorsedAlgorithms,
                         String[] extensionTypes) {
        this.symmetricKeyLength = symmetricKeyLength;
        this.certificatePath = certificatePath;
        this.appUsage = appUsage;
        this.friendlyName = friendlyName;
        this.endorsedAlgorithms = fillSet(endorsedAlgorithms);
        this.extensionTypes = fillSet(extensionTypes);
    }
}
