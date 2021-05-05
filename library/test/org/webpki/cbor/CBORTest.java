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

import java.io.File;
import java.io.IOException;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;

import java.util.EnumSet;
import java.util.GregorianCalendar;
import java.util.Locale;
import java.util.Vector;

import org.junit.BeforeClass;
import org.junit.Test;

import org.webpki.crypto.AsymSignatureAlgorithms;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;

import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;
import org.webpki.util.ISODateTime;

/**
 * CBOR JUnit suite
 */
public class CBORTest {

    @BeforeClass
    public static void openFile() throws Exception {
        Locale.setDefault(Locale.FRANCE);  // Should create HUGE problems :-)
        baseKey = System.clearProperty("json.keys") + File.separator;
    }

    static String baseKey;
    
    static String keyId;
    
    static KeyPair readJwk(String keyType) throws Exception {
        JSONObjectReader jwkPlus = JSONParser.parse(ArrayUtil.readFile(baseKey + keyType + "privatekey.jwk"));
        // Note: The built-in JWK decoder does not accept "kid" since it doesn't have a meaning in JSF or JEF. 
        if ((keyId = jwkPlus.getStringConditional("kid")) != null) {
            jwkPlus.removeProperty("kid");
        }
        return jwkPlus.getKeyPair();
    }

    void checkException(Exception e, String compareMessage) {
        String m = e.getMessage();
        String full = m;
        if (compareMessage.length() < m.length()) {
            m = m.substring(0, compareMessage.length());
        }
        if (!m.equals(compareMessage)) {
            fail("Exception: " + full);
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
        long dv = decodedInteger.getLong();
        assertTrue("Decoded value dv=" + dv + " v=" + value, decodedInteger.getLong() == value);
        String decString = decodedInteger.toString();
        String cString = cborObject.toString();
        assertTrue("Decoded string d=" + decString + 
                   " c=" + cString + " v=" + value + " f=" + forceUnsigned,
                   decString.equals(cString));
        BigInteger bigInteger = decodedInteger.getBigInteger();
        bigIntegerTest(bigInteger.toString(), hex);
        assertTrue("Big", cborObject.toString().equals(bigInteger.toString()));
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
        byte[] cbor = new CBORTextString(string).encode();
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
    
   void dateTimeTest(GregorianCalendar dateTime, 
                     EnumSet<ISODateTime.DatePatterns> format) throws IOException {
       CBORObject cborObject = new CBORDateTime(dateTime, format);
       byte[] cbor = cborObject.encode();
       CBORObject decoded = CBORObject.decode(cbor);
       assertTrue("Date", decoded.toString().equals(cborObject.toString()));
       assertTrue("Date 2", ArrayUtil.compare(cbor, decoded.encode()));
       GregorianCalendar decodedDateTime = decoded.getDateTime();
       assertTrue("Date 3 \nd=" + decodedDateTime.getTimeInMillis() + "\no=" + dateTime.getTimeInMillis(),
                  decodedDateTime.getTimeInMillis() / 1000 == dateTime.getTimeInMillis() / 1000);
    }
   
   void dateTimeTest(String hex, String isoNotation) throws IOException {
       CBORObject cbor = parseCborHex(hex);
       GregorianCalendar derived = cbor.getDateTime();
       GregorianCalendar actual = ISODateTime.parseDateTime(isoNotation, ISODateTime.COMPLETE);
       assertTrue("Date 4 \nd=" + derived.getTimeInMillis() + "\no=" + actual.getTimeInMillis(),
               derived.getTimeInMillis() == actual.getTimeInMillis());
   }

    @Test
    public void assortedTests() throws Exception {
        CBORArray cborArray = new CBORArray()
            .addElement(new CBORInteger(1))
            .addElement(new CBORArray()
                .addElement(new CBORInteger(2))
                .addElement(new CBORInteger(3)))
            .addElement(new CBORArray()
                .addElement(new CBORInteger(4))
                .addElement(new CBORInteger(5)));
        textCompare(cborArray,
                "[\n  1,\n  [\n    2,\n    3\n  ],\n  [\n    4,\n    5\n  ]\n]");
        binaryCompare(cborArray,"8301820203820405");

        cborArray = new CBORArray()
            .addElement(new CBORInteger(1))
            .addElement(new CBORTextStringMap()
                .setMappedValue("best", new CBORInteger(2))
                .setMappedValue("best2", new CBORInteger(3))
                .setMappedValue("another", new CBORInteger(4)))
            .addElement(new CBORArray()
                .addElement(new CBORInteger(5))
                .addElement(new CBORInteger(6)));
        textCompare(cborArray,
                "[\n  1,\n  {\n    \"best\": 2,\n    \"best2\": 3,\n    \"another\": 4\n  }," +
                "\n  [\n    5,\n    6\n  ]\n]");
        binaryCompare(cborArray,
                      "8301a36462657374026562657374320367616e6f7468657204820506");

        cborArray = new CBORArray()
            .addElement(new CBORInteger(1))
            .addElement(new CBORIntegerMap()
                .setMappedValue(8, new CBORInteger(2))
                .setMappedValue(58, new CBORInteger(3))
                .setMappedValue(-90, new CBORNull())
                .setMappedValue(-4, new CBORArray()
                    .addElement(new CBORBoolean(true))
                    .addElement(new CBORBoolean(false))))
            .addElement(new CBORArray()
                .addElement(new CBORInteger(4))
                .addElement(new CBORInteger(5)));
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
        
        bigIntegerTest("18446744073709551615", "1bffffffffffffffff");
        bigIntegerTest("18446744073709551614", "1bfffffffffffffffe");
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
                .addElement(new CBORInteger(1))
                .addElement(new CBORInteger(2))
                .addElement(new CBORInteger(3)), "83010203");
        
        dateTimeTest(new GregorianCalendar(), ISODateTime.UTC_NO_SUBSECONDS);
        dateTimeTest(new GregorianCalendar(), ISODateTime.LOCAL_NO_SUBSECONDS);
        dateTimeTest(new GregorianCalendar(), ISODateTime.COMPLETE);
        dateTimeTest("c074323032312d30352d30335430393a35303a30385a", 
                     "2021-05-03T09:50:08Z");
        dateTimeTest("c07819323032312d30352d30335431323a30333a33312b30323a3030", 
                     "2021-05-03T12:03:31+02:00");
        dateTimeTest("c07818323032312d30352d30335431303a30353a33302e3433315a", 
                     "2021-05-03T10:05:30.431Z");
        try {
            parseCborHex("c073323032312d30352d30335430393a35303a3038");
            fail("must not execute");
       } catch (Exception e) {
           checkException(e, "DateTime syntax error: 2021-05-03T09:50:08");
       }

    }
    
    class MapTest extends CBORMapBase {
        
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
         .insert(new CBORArray().addElement(new CBORInteger(100)))
         .insert(new CBORInteger(-1))
         .insert(new CBORBoolean(false))
         .insert(new CBORArray().addElement(new CBORInteger(-1)))
         .insert(new CBORInteger(100))
         .insert(new CBORTextString("aaa"))
         .insert(new CBORTextString("z"))
         .insert(new CBORTextString("aa"));
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
        try {
            parseCborHex("A20706636B657906");
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Mixing key types in the same map is not supported: INTEGER versus TEXT_STRING");
        }
        try {
            parseCborHex("A2F404F507");
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Only integer and text string map keys supported, found: BOOLEAN");
        }
    }

    @Test
    public void bufferTest() throws Exception {
        // To not "accidently" allocate potentially GBs of memory the
        // decoder uses a buffer scheme.
        // The assumption is that receive have already checked
        // that the CBOR code itself is within reason.
        int length = CBORObject.CBORDecoder.BUFFER_SIZE - 2;
        while (length < CBORObject.CBORDecoder.BUFFER_SIZE + 2) {
            byte[] byteString = new byte[length];
            for (int i = 0; i < length; i++) {
                byteString[i] = (byte) i;
            }
            byte[] cborData = new CBORByteString(byteString).encode();
            assertTrue("buf", 
                ArrayUtil.compare(byteString,
                                  ((CBORByteString)CBORObject.decode(cborData)).getByteString()));
            length++;
        }
    }
 
    @Test
    public void accessTest() throws Exception {
        CBORObject cbor = parseCborHex("8301a408022382f5f4183a033859f6820405");
        try {
            ((CBORArray) cbor).getElement(0).getIntegerMap();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "Is type: INTEGER, requested: INTEGER_MAP");
        }

        try {
            ((CBORArray) cbor).getElement(1).getIntegerMap().getMappedValue(-91).getInt();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "No such key: -91");
        }
        
        assertTrue("v1", ((CBORArray) cbor).getElement(1).getIntegerMap().getMappedValue(58).getInt() == 3);

        try {
            CBORObject unread = parseCborHex("17");
            unread.checkObjectForUnread();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Data of type=CBORInteger with value=23 was never read");
        }
    }

    @Test
    public void unreadElementTest() throws Exception {
        try {
            CBORObject unread = parseCborHex("8301a408022382f5f4183a033859f6820405");
            ((CBORArray) unread).getElement(0).getInt();
            unread.checkObjectForUnread();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Map key 8 of type=CBORInteger with value=2 was never read");
        }

        try {
            CBORObject unread = parseCborHex("8301a408022382f5f4183a033859f6820405");
            unread = ((CBORArray) unread).getElement(1).getIntegerMap();
            ((CBORIntegerMap)unread).getMappedValue(8).getInt();
            ((CBORArray)((CBORIntegerMap)unread).getMappedValue(-4)).getElement(0).getBoolean();
            unread.checkObjectForUnread();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Array element of type=CBORBoolean with value=false was never read");
        }

        // If you just want to mark an item as "read" you can use scan();
        try {
            CBORObject unread = parseCborHex("8301a408022382f5f4183a033859f6820405");
            unread = ((CBORArray) unread).getElement(1).getIntegerMap();
            ((CBORIntegerMap)unread).getMappedValue(8).getInt();
            ((CBORArray)((CBORIntegerMap)unread).getMappedValue(-4)).getElement(0).scan();
            unread.checkObjectForUnread();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Array element of type=CBORBoolean with value=false was never read");
        }

        // Getting an object without reading the value is considered as "unread".
        try {
            CBORObject unread = parseCborHex("8301a408022382f5f4183a033859f6820405");
            unread = ((CBORArray) unread).getElement(1).getIntegerMap();
            ((CBORIntegerMap)unread).getMappedValue(8).getInt();
            ((CBORArray)((CBORIntegerMap)unread).getMappedValue(-4)).getElement(0);
            unread.checkObjectForUnread();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Array element of type=CBORBoolean with value=true was never read");
        }
        
        try {
            CBORObject unread = parseCborHex("17");
            unread.checkObjectForUnread();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Data of type=CBORInteger with value=23 was never read");
        }

        try {
            CBORObject unread = parseCborHex("A107666D7964617461");
            unread.checkObjectForUnread();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Map key 7 of type=CBORTextString with value=\"mydata\" was never read");
        }

        try {
            CBORObject unread = parseCborHex("A0");
            unread.checkObjectForUnread();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Data of type=CBORTextStringMap with value={\n} was never read");
        }

        try {
            CBORObject unread = parseCborHex("80");
            unread.checkObjectForUnread();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Data of type=CBORArray with value=[\n] was never read");
        }
    }
    
    @Test
    public void typeCheckTest() throws Exception {
        CBORObject cborObject = parseCborHex("17");
        try {
            cborObject.getBoolean();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Is type: INTEGER, requested: BOOLEAN");
        }
        try {
            cborObject.getByteString();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Is type: INTEGER, requested: BYTE_STRING");
        }
    }

    @Test
    public void endOfFileTest() throws Exception {
         try {
            parseCborHex("83");
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Malformed CBOR, trying to read past EOF");
        }
    }

    @Test
    public void deterministicEncodingTest() throws Exception {
         try {
            parseCborHex("3800");
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Non-deterministic encoding: additional bytes form a zero value");
        }

        try {
            parseCborHex("c24900ffffffffffffffff");
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                 "Non-deterministic encoding: leading zero byte");
        }

        try {
            parseCborHex("c24101");
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                 "Non-deterministic encoding: bignum fits integer");
        }
    }
    
    CBORObject createDataToBeSigned() throws IOException {
        return new CBORIntegerMap()
        .setMappedValue(1, new CBORIntegerMap()
                .setMappedValue(1, new CBORTextString("Space Shop"))
                .setMappedValue(2, new CBORTextString("100.00"))
                .setMappedValue(3, new CBORTextString("EUR")))
            .setMappedValue(2, new CBORTextString("spaceshop.com"))
            .setMappedValue(3, new CBORTextString("FR7630002111110020050014382"))
            .setMappedValue(4, new CBORTextString("https://europeanpaymentsinitiative.eu/fwp"))
            .setMappedValue(5, new CBORTextString("62932"))
            .setMappedValue(6, new CBORDateTime("2021-05-03T09:50:08Z"));
    }
    
    void backAndForth(KeyPair keyPair) throws Exception {
        CBORObject cborPublicKey = CBORPublicKey.encodePublicKey(keyPair.getPublic());
        PublicKey publicKey = CBORPublicKey.decodePublicKey(cborPublicKey);
        assertTrue("PK" + cborPublicKey.toString(), publicKey.equals(keyPair.getPublic()));
    }
    
    CBORObject signAndVerify(CBORSigner signer, CBORValidator validator) 
            throws IOException, GeneralSecurityException {
        CBORObject tbs = createDataToBeSigned();
        tbs.getIntegerMap().sign(7, signer);
        byte[] sd = tbs.encode();
        CBORObject cborSd = CBORObject.decode(sd);
        cborSd.getIntegerMap().validate(7, validator);
        return tbs;
    }
   
    @Test
    public void signatureTest() throws Exception {
        KeyPair p256 = readJwk("p256");
        String keyIdP256 = keyId;
        KeyPair p256_2 = readJwk("p256-2");
        KeyPair p521 = readJwk("p521");
        KeyPair r2048 = readJwk("r2048");
        KeyPair x448 = readJwk("x448");
        KeyPair x25519 = readJwk("x25519");
        KeyPair ed448 = readJwk("ed448");
        KeyPair ed25519 = readJwk("ed25519");
        
        backAndForth(p256);
        backAndForth(r2048);
        backAndForth(x448);
        backAndForth(x25519);
        backAndForth(ed448);
        backAndForth(ed25519);
        
        signAndVerify(new CBORAsymKeySigner(p256.getPrivate()), 
                      new CBORAsymSignatureValidator(p256.getPublic()));

        signAndVerify(new CBORAsymKeySigner(p256.getPrivate()).setPublicKey(p256.getPublic()), 
                      new CBORAsymSignatureValidator(p256.getPublic()));

        signAndVerify(new CBORAsymKeySigner(ed25519.getPrivate()).setPublicKey(ed25519.getPublic()), 
                new CBORAsymSignatureValidator(ed25519.getPublic()));

        signAndVerify(new CBORAsymKeySigner(r2048.getPrivate()).setPublicKey(r2048.getPublic()), 
                new CBORAsymSignatureValidator(r2048.getPublic()));

        signAndVerify(new CBORAsymKeySigner(p256.getPrivate()), 
                new CBORAsymSignatureValidator(new CBORAsymSignatureValidator.KeyLocator() {
                    
                    @Override
                    public PublicKey locate(PublicKey optionalPublicKey, 
                                            String optionalKeyId,
                                            AsymSignatureAlgorithms signatureAlgorithm)
                            throws IOException, GeneralSecurityException {
                        return p256.getPublic();
                    }
                }));

        signAndVerify(new CBORAsymKeySigner(p256.getPrivate()), 
                new CBORAsymSignatureValidator(new CBORAsymSignatureValidator.KeyLocator() {
                    
                    @Override
                    public PublicKey locate(PublicKey optionalPublicKey, 
                                            String optionalKeyId,
                                            AsymSignatureAlgorithms signatureAlgorithm)
                            throws IOException, GeneralSecurityException {
                        return p256.getPublic();
                    }
                }));

        signAndVerify(new CBORAsymKeySigner(p256.getPrivate()).setKeyId(keyIdP256), 
                new CBORAsymSignatureValidator(new CBORAsymSignatureValidator.KeyLocator() {
                    
                    @Override
                    public PublicKey locate(PublicKey optionalPublicKey, 
                                            String optionalKeyId,
                                            AsymSignatureAlgorithms signatureAlgorithm)
                            throws IOException, GeneralSecurityException {
                        return keyIdP256.equals(optionalKeyId) ? 
                                              p256.getPublic() : p256_2.getPublic();
                    }
                }));
        
        
        signAndVerify(new CBORAsymKeySigner(p256.getPrivate()).setPublicKey(p256.getPublic()), 
                new CBORAsymSignatureValidator(new CBORAsymSignatureValidator.KeyLocator() {
                    
                    @Override
                    public PublicKey locate(PublicKey optionalPublicKey, 
                                            String optionalKeyId,
                                            AsymSignatureAlgorithms signatureAlgorithm)
                            throws IOException, GeneralSecurityException {
                        assertTrue("pk", p256.getPublic().equals(optionalPublicKey));
                        return null;
                    }
                }));

        try {
            signAndVerify(new CBORAsymKeySigner(p256.getPrivate()), 
                    new CBORAsymSignatureValidator(new CBORAsymSignatureValidator.KeyLocator() {
                        
                        @Override
                        public PublicKey locate(PublicKey optionalPublicKey, 
                                                String optionalKeyId,
                                                AsymSignatureAlgorithms signatureAlgorithm)
                                throws IOException, GeneralSecurityException {
                            return p256_2.getPublic();
                        }
                    }));
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "Bad signature for key: ");
        }

        try {
            signAndVerify(new CBORAsymKeySigner(p256.getPrivate(), AsymSignatureAlgorithms.ED25519)
                    .setPublicKey(p256.getPublic()), 
                    new CBORAsymSignatureValidator(p256.getPublic()));
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Supplied key (NIST_P_256) is incompatible with specified algorithm (ED25519)");
        }
        
        try {
            signAndVerify(new CBORAsymKeySigner(p256.getPrivate()).setPublicKey(p256.getPublic()), 
                    new CBORAsymSignatureValidator(p256_2.getPublic()));
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "Public keys not identical");
        }
        
        try {
            signAndVerify(new CBORAsymKeySigner(p256.getPrivate()), 
                    new CBORAsymSignatureValidator(ed25519.getPublic()));
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "Algorithm ECDSA_SHA256 does not match key type ED25519");
        }
        
        try {
            signAndVerify(new CBORAsymKeySigner(p256.getPrivate()), 
                    new CBORAsymSignatureValidator(new CBORAsymSignatureValidator.KeyLocator() {
                        
                        @Override
                        public PublicKey locate(PublicKey optionalPublicKey, 
                                                String optionalKeyId,
                                                AsymSignatureAlgorithms signatureAlgorithm)
                                throws IOException, GeneralSecurityException {
                            if ("otherkey".equals(optionalKeyId)) {
                                return p256_2.getPublic();
                            }
                            throw new IOException("KeyId = " + optionalKeyId);
                        }
                    }));
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "KeyId = null");
        }
        
    }
}
