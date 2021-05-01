/*
 *  Copyright 2006-2021 WebPKI.org (http://webpki.org).
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
import static org.junit.Assert.fail;

import java.io.IOException;

import java.math.BigInteger;

import java.util.Vector;

import org.junit.Test;

import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;


/**
 * CBOR JUnit suite
 */
public class CBORTest {

    void checkException(Exception e, String compareMessage) {
        String m = e.getMessage();
        if (compareMessage != null && !m.equals(compareMessage)) {
            fail("Exception: " + m);
        }
    }
    
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

    CBORObject parseCborHex(String hex) throws IOException {
        return CBORObject.decode(DebugFormatter.getByteArrayFromHex(hex));
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
        BigInteger bigInteger = decodedInteger.getBigInteger();
        bigIntegerTest(bigInteger.toString(), hex);
        assertTrue("Big", cborObject.getBigInteger().toString().equals(bigInteger.toString()));
    }

    void integerTest(long value, String hex) throws Exception {
        integerTest(value, false, false, hex);
    }
    
    void integerTest(String value) throws Exception {
        CBORObject integer = new CBORInteger(new BigInteger(value));
        byte[] cbor = integer.encode();
        CBORInteger res = (CBORInteger)CBORObject.decode(cbor);
        assertTrue("intBig", res.toString().equals(value));
    }

    void bigIntegerTest(String value, String hex) throws Exception {
        byte[] cbor = new CBORBigInteger(new BigInteger(value)).encode();
        String calc = DebugFormatter.getHexString(cbor);
        assertTrue("big int=" + value + " c=" + calc + " h=" + hex,
                hex.equals(DebugFormatter.getHexString(cbor)));
        CBORObject decodedBig = CBORObject.decode(cbor);
        String decS = decodedBig.getBigInteger().toString();
        assertTrue("Big2 d=" + decS + " v=" + value, value.equals(decS));
    }

    void stringTest(String string, String hex) throws Exception {
        byte[] cbor = new CBORString(string).encode();
        String calc = DebugFormatter.getHexString(cbor);
        assertTrue("string=" + string + " c=" + calc + " h=" + hex, hex.equals(calc));
        assertTrue("string 2", CBORObject.decode(cbor).toString().equals("\"" + string + "\""));
    }

    void arrayTest(CBORArray cborArray, String hex) throws Exception {
        byte[] cbor = cborArray.encode();
        String calc = DebugFormatter.getHexString(cbor);
        assertTrue(" c=" + calc + " h=" + hex, hex.equals(calc));
        assertTrue("arr", CBORObject.decode(cbor).toString().equals(cborArray.toString()));
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
                .setObject(58, new CBORInteger(3))
                .setObject(-90, new CBORNull())
                .setObject(-4, new CBORArray()
                        .addObject(new CBORBoolean(true))
                        .addObject(new CBORBoolean(false))))
            .addObject(new CBORArray()
                .addObject(new CBORInteger(4))
                .addObject(new CBORInteger(5)));
        textCompare(cborArray,
                "[\n  1,\n  {\n    8: 2,\n    -4: [\n" +
                "      true,\n      false\n    ],\n    58: 3,\n    -90: null\n  }," +
                "\n  [\n    4,\n    5\n  ]\n]");
        binaryCompare(cborArray,"8301a408022382f5f4183a033859f6820405");
        
        integerTest(0, "00" );
        integerTest(1, "01");
        integerTest(10, "0a");
        integerTest(23, "17");
        integerTest(24, "1818");
        integerTest(25, "1819");
        integerTest(100, "1864");
        integerTest(1000, "1903e8");
        integerTest(255, "18ff");
        integerTest(256, "190100");
        integerTest(-255, "38fe");
        integerTest(-256, "38ff");
        integerTest(-257, "390100");
        integerTest(65535, "19ffff");
        integerTest(65536, "1a00010000");
        integerTest(-65535, "39fffe");
        integerTest(-65536, "39ffff");
        integerTest(-65537, "3a00010000");
        integerTest(1000000, "1a000f4240");
        integerTest(1000000000000L,      "1b000000e8d4a51000");
        /* Added because of java.. */
        integerTest(Long.MIN_VALUE, "3b7fffffffffffffff");
        integerTest(0x8000000000000000L, true, true,      "1b8000000000000000");
        integerTest(0xffffffffffffffffL, true, true,      "1bffffffffffffffff");
        integerTest(0xfffffffffffffffeL, true, true,      "1bfffffffffffffffe");
        integerTest(0,                  false, true,      "3bffffffffffffffff");
        
        integerTest("8");
        integerTest("18446744073709551615");
        integerTest("-18446744073709551616");
        try {
            integerTest("-18446744073709551617");
            fail("must not execute");
        } catch (Exception e) {
           checkException(e, "Value out of range for CBORInteger"); 
        }
        try {
            integerTest("18446744073709551616");
            fail("must not execute");
        } catch (Exception e) {
           checkException(e, "Value out of range for CBORInteger"); 
        }
        
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
        bigIntegerTest("-1", "20");
 
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

    @Test
    public void bufferTest() throws Exception {
        int length = CBORObject.CBORDecoder.BUFFER_SIZE - 2;
        while (length < CBORObject.CBORDecoder.BUFFER_SIZE + 2) {
            byte[] byteArray = new byte[length];
            for (int i = 0; i < length; i++) {
                byteArray[i] = (byte) i;
            }
            byte[] cborData = new CBORByteArray(byteArray).encode();
            assertTrue("buf", 
                ArrayUtil.compare(byteArray,
                                  ((CBORByteArray)CBORObject.decode(cborData)).getByteArray()));
            length++;
        }
    }
 
    @Test
    public void accessTest() throws Exception {
        CBORObject cbor = parseCborHex("8301a408022382f5f4183a033859f6820405");
        try {
            ((CBORArray) cbor).getObject(0).getIntegerMap();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "Is type: INTEGER, requested: INTEGER_MAP");
        }

        try {
            ((CBORArray) cbor).getObject(1).getIntegerMap().getInt32(-91);
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "No such key: -91");
        }
        
        assertTrue("v1", ((CBORArray) cbor).getObject(1).getIntegerMap().getInt32(58) == 3);

        try {
            CBORObject unread = parseCborHex("17");
            unread.checkObjectForUnread();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "Data of type=CBORInteger with value=23 was never read");
        }
    }

    @Test
    public void unreadElementTest() throws Exception {
        try {
            CBORObject unread = parseCborHex("8301a408022382f5f4183a033859f6820405");
            ((CBORArray) unread).getInt32(0);
            unread.checkObjectForUnread();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "Map key 8 of type=CBORInteger with value=2 was never read");
        }

        try {
            CBORObject unread = parseCborHex("8301a408022382f5f4183a033859f6820405");
            unread = ((CBORArray) unread).getObject(1).getIntegerMap();
            ((CBORIntegerMap)unread).getBigInteger(8);
            ((CBORArray)((CBORIntegerMap)unread).getObject(-4)).getObject(0);
            unread.checkObjectForUnread();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "Array element of type=CBORBoolean with value=false was never read");
        }

        try {
            CBORObject unread = parseCborHex("17");
            unread.checkObjectForUnread();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "Data of type=CBORInteger with value=23 was never read");
        }
    }
}
