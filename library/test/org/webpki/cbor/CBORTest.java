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

import static org.junit.Assert.assertTrue;

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
        byte[] cbor = cborObject.encode();
        String actual = DebugFormatter.getHexString(cbor);
        hex = hex.toLowerCase();
        assertTrue("binary h=" + hex + " c=" + actual, hex.equals(actual));
        CBORObject cborO = CBORObject.decode(cbor);
        String decS = cborO.toString();
        String origS = cborObject.toString();
        assertTrue("bc d=" + decS + " o=" + origS, decS.equals(origS));
    }

    void textCompare(CBORObject cborObject, String text) throws Exception {
        String actual = cborObject.toString();
        assertTrue("text=\n" + actual + "\n" + text, text.equals(actual));
    }
    
    void integerTest(long value, boolean forceUnsigned, boolean set, String hex) throws Exception {
        CBORObject cborObject = set ? 
                new CBORInteger(value, forceUnsigned) : new CBORInteger(value);
        byte[] cbor = cborObject.encode();
        String calc = DebugFormatter.getHexString(cbor);
        assertTrue("int=" + value + " c=" + calc + " h=" + hex, hex.equals(calc));
        CBORObject decodedInteger = CBORObject.decode(cbor);
        long dv = decodedInteger.getInt64();
        assertTrue("Decoded value dv=" + dv + " v=" + value, decodedInteger.getInt64() == value);
        String decString = decodedInteger.toString();
        String cString = cborObject.toString();
        assertTrue("Decoded string d=" + decString + 
                   " c=" + cString + " v=" + value + " f=" + forceUnsigned,
                   decString.equals(cString));
        BigInteger bigInteger = BigInteger.valueOf(value);
        if (forceUnsigned) {
            bigInteger = bigInteger.and(CBORBigInteger.MAX_INT64);
        }
        bigIntegerTest(bigInteger.toString(), hex);
        assertTrue("Big", cborObject.getBigInteger().toString().equals(bigInteger.toString()));
    }
    
    void integerTest(long value, String hex) throws Exception {
        integerTest(value, false, false, hex);
    }
    
    void bigIntegerTest(String value, String hex) throws Exception {
        byte[] cbor = new CBORBigInteger(new BigInteger(value)).encode();
        String calc = DebugFormatter.getHexString(cbor);
        assertTrue("big int=" + value + " c=" + calc + " h=" + hex,
                hex.equals(DebugFormatter.getHexString(cbor)));
        CBORObject decodedBig = CBORObject.decode(cbor);
        String decS = decodedBig.getBigInteger().toString();
        assertTrue("Big2 d=" + decS + " v=" + value, value.equals(decS));
        /*
        if (!value.equals(decS)) {
            fail("t=" + decodedBig.getType() + " d=" + decS + 
                    " v=" + value +
                    " iv=" + ((CBORInteger)decodedBig).value +
                    " if=" + ((CBORInteger)decodedBig).forceUnsigned +
                    " ix=" + ((CBORInteger)decodedBig).explicit);
        }
                    */
    }
    
    void stringTest(String string, String hex) throws Exception {
        byte[] cbor = new CBORString(string).encode();
        String calc = DebugFormatter.getHexString(cbor);
        assertTrue("string=" + string + " c=" + calc + " h=" + hex, hex.equals(calc));
    }
    
    void arrayTest(CBORArray cborArray, String hex) throws Exception {
        byte[] cbor = cborArray.encode();
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
                "[\n  1,\n  [\n    2,\n    3\n  ],\n  [\n    4,\n    5\n  ]\n]");
        binaryCompare(cborArray,"8301820203820405");

        cborArray = new CBORArray()
            .addObject(new CBORInteger(1))
            .addObject(new CBORStringMap()
                .setObject("best", new CBORInteger(2))
                .setObject("best2", new CBORInteger(3))
                .setObject("another", new CBORInteger(4)))
            .addObject(new CBORArray()
                .addObject(new CBORInteger(5))
                .addObject(new CBORInteger(6)));
        textCompare(cborArray,
                "[\n  1,\n  {\n    \"best\": 2,\n    \"best2\": 3,\n    \"another\": 4\n  }," +
                "\n  [\n    5,\n    6\n  ]\n]");
        binaryCompare(cborArray,
                      "8301a36462657374026562657374320367616e6f7468657204820506");

        cborArray = new CBORArray()
            .addObject(new CBORInteger(1))
            .addObject(new CBORIntegerMap()
                .setObject(8, new CBORInteger(2))
                .setObject(58, new CBORInteger(3)))
            .addObject(new CBORArray()
                .addObject(new CBORInteger(4))
                .addObject(new CBORInteger(5)));
        textCompare(cborArray,
                "[\n  1,\n  {\n    8: 2,\n    58: 3\n  }," +
                "\n  [\n    4,\n    5\n  ]\n]");
        binaryCompare(cborArray,"8301a20802183a03820405");
        
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
        integerTest(0x8000000000000000L, true, true,      "1b8000000000000000");
        integerTest(0xffffffffffffffffL, true, true,      "1bffffffffffffffff");

        bigIntegerTest("18446744073709551615",  "1bffffffffffffffff");
        bigIntegerTest("18446744073709551614",  "1bfffffffffffffffe");
        bigIntegerTest("18446744073709551616",  "c249010000000000000000");
        bigIntegerTest(new BigInteger("ff0000000000000000", 16).toString(),
                       "c249ff0000000000000000");
        bigIntegerTest(new BigInteger("800000000000000000", 16).toString(),
                       "c249800000000000000000");
        bigIntegerTest(new BigInteger("7f0000000000000000", 16).toString(),
                       "c2497f0000000000000000");
        bigIntegerTest("-18446744073709551616", "3bffffffffffffffff");
        bigIntegerTest("-18446744073709551615", "3bfffffffffffffffe");
        bigIntegerTest("-18446744073709551617", "c349010000000000000000");
        bigIntegerTest("65535", "19ffff");
    //    bigIntegerTest("-1", "20");
 
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
    
    static String[] RFC8949_SORTING = {
            "10", 
            "100",
            "-1",
            "\"z\"",
            "\"aa\"",
            "\"aaa\"",
            "[100]",
            "[-1]",
            "false"
    };
    
    static String[] RFC7049_SORTING = {
            "10", 
            "-1",
            "false",
            "100",
            "\"z\"",
            "[-1]",
            "\"aa\"",
            "[100]",
            "\"aaa\""
    };
    
    void sortingTest(String[] expectedOrder) throws Exception{
        MapTest m = new MapTest();
        m.insert(new CBORInteger(10))
         .insert(new CBORArray().addObject(new CBORInteger(100)))
         .insert(new CBORInteger(-1))
         .insert(new CBORBoolean(false))
         .insert(new CBORArray().addObject(new CBORInteger(-1)))
         .insert(new CBORInteger(100))
         .insert(new CBORString("aaa"))
         .insert(new CBORString("z"))
         .insert(new CBORString("aa"));
        String total = m.toString().replace(" ", "").replace("\n","");
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
            String expected = expectedOrder[i++];
            assertTrue("key=" + key + " exp=" + expected, key.equals(expected));
        }
    }
    
    @Test
    public void mapperTest() throws Exception {
        sortingTest(RFC7049_SORTING);
        CBORMapBase.setRfc7049SortingMode(false);
        sortingTest(RFC8949_SORTING);
    }
}
