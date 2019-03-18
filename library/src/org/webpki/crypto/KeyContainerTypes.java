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
package org.webpki.crypto;

import java.io.IOException;

import java.util.LinkedHashSet;
import java.util.Vector;


public enum KeyContainerTypes {

    SOFTWARE ("software"),
    EMBEDDED ("embedded"),  // TPM, SKS, TEE, TXT
    UICC     ("uicc"),      // SIM card
    SD_CARD  ("sdcard"),
    EXTERNAL ("external");  // Smart card, Net-HSM

    String name;

    KeyContainerTypes(String name) {
        this.name = name;
    }

    public static final String KCT_TARGET_KEY_CONTAINERS = "targetKeyContainers";

    public String getName() {
        return name;
    }

    public static KeyContainerTypes getKeyContainerType(String arg) throws IOException {
        for (KeyContainerTypes type : values()) {
            if (type.toString().equalsIgnoreCase(arg)) {
                return type;
            }
        }
        throw new IOException("Bad container name: " + arg);
    }

    static class KeyContainerListParser {

        LinkedHashSet<String> keyContainerTypes = new LinkedHashSet<String>();

        KeyContainerListParser(String[] listOfGrantedTypes) throws IOException {
            if (listOfGrantedTypes != null) {
                if (listOfGrantedTypes.length == 0) {
                    throw new IOException("Empty list not allowed");
                }
                for (String type : listOfGrantedTypes) {
                    if (!keyContainerTypes.add(getKeyContainerType(type).getName())) {
                        throw new IOException("Duplicate key container type: " + type);
                    }
                }
            }
        }

        String[] normalized() {
            if (keyContainerTypes.isEmpty()) {
                return null;
            }
            return keyContainerTypes.toArray(new String[0]);
        }
    }

    public static String[] parseOptionalKeyContainerList(String[] listOfGrantedTypes) throws IOException {
        return new KeyContainerListParser(listOfGrantedTypes).normalized();
    }

    public static String[] parseOptionalKeyContainerList(KeyContainerTypes[] listOfGrantedTypes) throws IOException {
        if (listOfGrantedTypes == null) {
            return null;
        }
        Vector<String> list = new Vector<String>();
        for (KeyContainerTypes type : listOfGrantedTypes) {
            list.add(type.getName());
        }
        return parseOptionalKeyContainerList(list.toArray(new String[0]));
    }

    public static LinkedHashSet<KeyContainerTypes> getOptionalKeyContainerSet(String[] listOfGrantedTypes) throws IOException {
        String[] list = parseOptionalKeyContainerList(listOfGrantedTypes);
        if (list == null) {
            return null;
        }
        LinkedHashSet<KeyContainerTypes> set = new LinkedHashSet<KeyContainerTypes>();
        for (String type : list) {
            set.add(getKeyContainerType(type));
        }
        return set;
    }
}
