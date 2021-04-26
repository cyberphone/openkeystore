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
import java.math.BigInteger;
import java.util.Vector;

import org.junit.Test;
import org.webpki.util.DebugFormatter;


/**
 * CBOR JUnit suite
 */
public class CBORTest {

    void binaryCompare(CBORObject cborObject, String hex) throws Exception {
        String actual = DebugFormatter
                    .getHexString(cborObject.writeObject());
        hex = hex.toLowerCase();
        assertTrue("binary h=" + hex + " c=" + actual, hex.equals(actual));
    }

    void textCompare(CBORObject cborObject, String text) throws Exception {
        String actual = cborObject.toString();
        System.out.println(actual);
 //       assertTrue("text", text.equals(actual));
    }
    
    void integerTest(long value, boolean forceUnsigned, String hex) throws Exception {
        byte[] cbor = new CBORInteger(value, forceUnsigned).writeObject();
        String calc = DebugFormatter.getHexString(cbor);
        assertTrue("int=" + value + " c=" + calc + " h=" + hex, hex.equals(calc));
    }
    
    void integerTest(long value, String hex) throws Exception {
        integerTest(value, false, hex);
    }
    
    void bigIntegerTest(String value, String hex) throws Exception {
        BigInteger bigInteger = new BigInteger(value);
 //       big.
 //       byte[] cbor = new CBORInteger(value).writeObject();
 //       assertTrue("int=" + value, hex.equals(DebugFormatter.getHexString(cbor)));
    }
    
    void stringTest(String string, String hex) throws Exception {
        byte[] cbor = new CBORString(string).writeObject();
        String calc = DebugFormatter.getHexString(cbor);
        assertTrue("string=" + string + " c=" + calc + " h=" + hex, hex.equals(calc));
    }
    
    void arrayTest(CBORArray cborArray, String hex) throws Exception {
        byte[] cbor = cborArray.writeObject();
        String calc = DebugFormatter.getHexString(cbor);
        assertTrue(" c=" + calc + " h=" + hex, hex.equals(calc));
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
        /*
        binaryCompare(cborArray,
                      "8301a36462657374026562657374320267616e6f7468657203820405");
                      */

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
        /*
        binaryCompare(cborArray,"8301a2183a030802820405");
        */
        
        integerTest(0, "00" );
        integerTest(1, "01");
        integerTest(10, "0a");
        integerTest(23, "17");
        integerTest(24, "1818");
        integerTest(25, "1819");
        integerTest(100, "1864");
        integerTest(1000, "1903e8");
        integerTest(1000000, "1a000f4240");
        integerTest(1000000000000L,      "1b000000e8d4a51000");
        /* Added because of java.. */
        integerTest(Long.MIN_VALUE, "3b7fffffffffffffff");
        integerTest(0x8000000000000000L, true,       "1b8000000000000000");
        integerTest(0xffffffffffffffffL, true,       "1bffffffffffffffff");
 
        /* Dropped because they are too weird :)
        bigIntegerTest("18446744073709551615",  "1bffffffffffffffff");
        bigIntegerTest("18446744073709551616",  "c249010000000000000000");
        bigIntegerTest("-18446744073709551616", "3bffffffffffffffff");
        bigIntegerTest("-18446744073709551617", "c349010000000000000000");
        */
        integerTest(-1, "20");
        integerTest(-10, "29");
        integerTest(-100, "3863");
        integerTest(-1000, "3903e7");
         
        stringTest("", "60");
        stringTest("IETF", "6449455446");
        stringTest("\ud800\udd51", "64f0908591");
        stringTest("1234567890abcdefghijklmnofpqrstxyz", 
                   "7822313233343536373839306162636465666768696a6b6c6d6e6f66707172737478797a");
        
        arrayTest(new CBORArray(), "80");
        arrayTest(new CBORArray()
                .addObject(new CBORInteger(1))
                .addObject(new CBORInteger(2))
                .addObject(new CBORInteger(3)), "83010203");
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
        i = 0;
        for (String key : keys) {
            assertTrue("key=" + key, key.equals(expectedOrder[i++]));
        }
    }
    
    @Test
    public void mapperTest() throws Exception {
        sortingTest(NEW_SORTING);
        CBORMapBase.setRfc7049SortingMode(false);
        sortingTest(OLD_SORTING);
    }
}
