/*
 *  Copyright 2006-2020 WebPKI.org (http://webpki.org).
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
package org.webpki.cbor;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.Vector;

import org.junit.Test;
import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;


/**
 * CBOR JUnit suite
 */
public class CBORTest {

    void binaryCompare(CBORObject cborObject, String hex) throws Exception {
        String actual = DebugFormatter
                    .getHexString(cborObject.writeObject());
        System.out.println(actual);
        hex = hex.toLowerCase();
 //       assertTrue("binary", hex.equals(actual));
    }

    void textCompare(CBORObject cborObject, String text) throws Exception {
        String actual = cborObject.toString();
        System.out.println(actual);
 //       assertTrue("text", text.equals(actual));
    }
    
    @Test
    public void assortedTests() throws Exception {
        CBORArray cborArray = new CBORArray()
            .addObject(new CBORInteger(1))
            .addObject(new CBORArray()
                .addObject(new CBORInteger(2))
                .addObject(new CBORInteger(3)))
            .addObject(new CBORArray()
                .addObject(new CBORInteger(4))
                .addObject(new CBORInteger(5)));
        textCompare(cborArray,
                "[\n  1,\n  [\n    2,\n    3],\n  [\n    4,\n  ]\n]\n");
        binaryCompare(cborArray,"8301820203820405");

        cborArray = new CBORArray()
            .addObject(new CBORInteger(1))
            .addObject(new CBORStringMap()
                .setObject("best", new CBORInteger(2))
                .setObject("best2", new CBORInteger(2))
                .setObject("another", new CBORInteger(3)))
            .addObject(new CBORArray()
                .addObject(new CBORInteger(4))
                .addObject(new CBORInteger(5)));
        textCompare(cborArray,
                "[\n  1,\n  [\n    2,\n    3],\n  [\n    4,\n  ]\n]\n");
        binaryCompare(cborArray,"8301820203820405");

        cborArray = new CBORArray()
            .addObject(new CBORInteger(1))
            .addObject(new CBORIntegerMap()
                .setObject(8, new CBORInteger(2))
                .setObject(58, new CBORInteger(3)))
            .addObject(new CBORArray()
                .addObject(new CBORInteger(4))
                .addObject(new CBORInteger(5)));
        textCompare(cborArray,
                "[\n  1,\n  [\n    2,\n    3],\n  [\n    4,\n  ]\n]\n");
        binaryCompare(cborArray,"8301820203820405");
    }
    
    class MapTest extends CBORMapBase {
        private static final long serialVersionUID = 1L;
        
        int objectNumber;
        MapTest insert(CBORObject key) throws IOException {
            setObject(key, new CBORInteger(objectNumber++));
            return this;
        }
    }
    
    static String[] NEW_SORTING = {
            "10", 
            "100",
            "-1",
            "\"z\"",
            "\"aa\"",
            "[100]",
            "[-1]",
            "false"
    };
    
    static String[] OLD_SORTING = {
            "10", 
            "-1",
            "false",
            "100",
            "\"z\"",
            "[-1]",
            "\"aa\"",
            "[100]"
    };
    
    void sortingTest(String[] expectedOrder) throws Exception{
        MapTest m = new MapTest();
        m.insert(new CBORInteger(10))
         .insert(new CBORInteger(-1))
         .insert(new CBORBoolean(false))
         .insert(new CBORInteger(100))
         .insert(new CBORString("z"))
         .insert(new CBORArray().addObject(new CBORInteger(-1)))
         .insert(new CBORString("aa"))
         .insert(new CBORArray().addObject(new CBORInteger(100)));
        String total = m.toString().replace(" ", "").replace("\n","");
        System.out.println(total);
        Vector<String> keys = new Vector<>();
        int i = 1;
        int stop;
        while (true) {
            stop = total.indexOf(':', i);
            if (stop < 0) {
                break;
            }
            keys.add(total.substring(i, stop));
            i = total.indexOf(',', stop);
            if (i > 0) {
                i++;
            } else {
                break;
            }
        }
        for (String key : keys) {
            System.out.println(key);
        }
    }
    
    @Test
    public void mapperTest() throws Exception {
        sortingTest(OLD_SORTING);
        CBORMapBase.setRfc7049SortingMode(false);
        sortingTest(NEW_SORTING);
    }
}
