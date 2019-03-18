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
package org.webpki.xml;

import java.util.Date;

import java.text.SimpleDateFormat;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.XMLSchemaCache;

public class performance {
    static void timeout(String message) {
        System.out.println(message + ": " + new SimpleDateFormat("HH:mm:ss").format(new Date()));
    }

    public static void main(String argv[]) throws Exception {
        if (argv.length < 3) {
            System.out.println("Usage: " + performance.class.getName() + "  count  schema_1_class [schema_2_class ... schema_n_class]  xml_doc");
            System.exit(3);
        }
        int last = argv.length - 1;
        byte[] xml_data = ArrayUtil.readFile(argv[last]);
        int count = Integer.valueOf(argv[0]);
        timeout("XML Schema Cache Init");
        XMLSchemaCache xmlp = new XMLSchemaCache();
        for (int i = 1; i < last; i++) {
            xmlp.addWrapper(argv[i]);
        }
        timeout("XML Schema Validation Only");
        for (int i = 0; i < count; i++) {
            xmlp.validate(xml_data);
        }
        timeout("XML Object Deserialization");
        for (int i = 0; i < count; i++) {
            xmlp.parse(xml_data);
        }
        timeout("Done");
    }

}
