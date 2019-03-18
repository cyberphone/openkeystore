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
import java.util.Set;

public enum PatternRestriction {

    TWO_IN_A_ROW   ("two-in-a-row",   SecureKeyStore.PIN_PATTERN_TWO_IN_A_ROW),    // "11342" is flagged
    THREE_IN_A_ROW ("three-in-a-row", SecureKeyStore.PIN_PATTERN_THREE_IN_A_ROW),  // "111342" is flagged
    SEQUENCE       ("sequence",       SecureKeyStore.PIN_PATTERN_SEQUENCE),        // "abcdef" is flagged
    REPEATED       ("repeated",       SecureKeyStore.PIN_PATTERN_REPEATED),        // "abcdec" is flagged
    MISSING_GROUP  ("missing-group",  SecureKeyStore.PIN_PATTERN_MISSING_GROUP);   // The PIN must be "alphanumeric" and contain a mix of
    // letters, digits and punctuation characters

    private final String name;         // As expressed in protocols

    private final byte sks_mask;       // As expressed in SKS

    private PatternRestriction(String name, byte sks_mask) {
        this.name = name;
        this.sks_mask = sks_mask;
    }


    public String getProtocolName() {
        return name;
    }


    public byte getSKSMaskBit() {
        return sks_mask;
    }


    public static PatternRestriction getPatternRestrictionFromString(String name) throws IOException {
        for (PatternRestriction restriction : PatternRestriction.values()) {
            if (name.equals(restriction.name)) {
                return restriction;
            }
        }
        throw new IOException("Unknown \"" + SecureKeyStore.VAR_PATTERN_RESTRICTIONS + "\": " + name);
    }


    public static byte getSksValue(Set<PatternRestriction> patterns) {
        byte result = 0;
        for (PatternRestriction pattern : patterns) {
            result |= pattern.sks_mask;
        }
        return result;
    }

}
