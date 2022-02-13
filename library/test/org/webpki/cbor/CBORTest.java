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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import java.util.Locale;
import java.util.Vector;

import org.junit.BeforeClass;
import org.junit.Test;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.HmacAlgorithms;
import org.webpki.crypto.HmacSignerInterface;
import org.webpki.crypto.KeyEncryptionAlgorithms;
import org.webpki.crypto.SignatureWrapper;
import org.webpki.crypto.X509SignerInterface;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.EncryptionCore;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;
import org.webpki.json.SymmetricKeys;

import org.webpki.util.ArrayUtil;
import org.webpki.util.HexaDecimal;
import org.webpki.util.PEMDecoder;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * CBOR JUnit suite
 */
public class CBORTest {

    @BeforeClass
    public static void openFile() throws Exception {
        Locale.setDefault(Locale.FRANCE);  // Should create HUGE problems :-)
        baseKey = System.clearProperty("json.keys") + File.separator;
        CustomCryptoProvider.forcedLoad(false);
        dataToEncrypt = "The brown fox jumps over the lazy bear".getBytes("utf-8");
        symmetricKeys = new SymmetricKeys(baseKey);
        p256 = readJwk("p256");
        keyIdP256 = keyId;
        p256_2 = readJwk("p256-2");
        p521 = readJwk("p521");
        r2048 = readJwk("r2048");
        x448 = readJwk("x448");
        x25519 = readJwk("x25519");
        ed448 = readJwk("ed448");
        ed25519 = readJwk("ed25519");
        p256CertPath = PEMDecoder.getCertificatePath(ArrayUtil.readFile(baseKey + "p256certpath.pem"));
    }
    
    static byte[] dataToEncrypt;
    
    static String baseKey;
    
    static SymmetricKeys symmetricKeys;

    static KeyPair p256;
    static CBORObject keyIdP256;
    static X509Certificate[] p256CertPath;
    static KeyPair p256_2;
    static KeyPair p521;
    static KeyPair r2048;
    static KeyPair x448;
    static KeyPair x25519;
    static KeyPair ed448;
    static KeyPair ed25519;
    static CBORObject keyId;
    
    enum IntegerVariations {LONG, ULONG, INT};
    
    static KeyPair readJwk(String keyType) throws Exception {
        JSONObjectReader jwkPlus = JSONParser.parse(ArrayUtil.readFile(baseKey + keyType + "privatekey.jwk"));
        // Note: The built-in JWK decoder does not accept "kid" since it doesn't have a meaning in JSF or JEF. 
        keyId = new CBORTextString(jwkPlus.getString("kid"));
        jwkPlus.removeProperty("kid");
        return jwkPlus.getKeyPair();
    }

    void checkException(Exception e, String compareMessage) {
        String m = e.getMessage();
        String full = m;
        if (compareMessage.length() < m.length()) {
            m = m.substring(0, compareMessage.length());
        }
        if (!m.equals(compareMessage)) {
            fail("Exception: " + full + "\ncompare: " + compareMessage);
        }
    }
    
    void binaryCompare(CBORObject cborObject, String hex) throws Exception {
        byte[] cbor = cborObject.encode();
        String actual = HexaDecimal.encode(cbor);
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
        byte[] cbor = HexaDecimal.decode(hex);
        CBORObject cborObject = CBORObject.decode(cbor);
        assertTrue("phex: " + hex, ArrayUtil.compare(cbor, cborObject.encode()));
        return cborObject;
    }

    void integerTest(long value, boolean forceUnsigned, boolean set, String hex) throws Exception {
        CBORObject cborObject = set ? 
                new CBORInteger(value, forceUnsigned) : new CBORInteger(value);
        byte[] cbor = cborObject.encode();
        String calc = HexaDecimal.encode(cbor);
        assertTrue("int=" + value + " c=" + calc + " h=" + hex, hex.equals(calc));
        CBORObject decodedInteger = CBORObject.decode(cbor);
        if (value != -1 || forceUnsigned) {
            long dv = forceUnsigned ? decodedInteger.getUnsignedLong() : decodedInteger.getLong();
            assertTrue("Decoded value dv=" + dv + " v=" + value, dv == value);
        }
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
    
    void integerTest(String value, IntegerVariations variation, boolean mustFail)
            throws Exception {
        CBORObject bigInteger = new CBORInteger(new BigInteger(value));
        byte[] cbor = bigInteger.encode();
        CBORInteger res = (CBORInteger)CBORObject.decode(cbor);
        assertTrue("intBig", res.toString().equals(value));
        if (mustFail) {
            try {
                switch (variation) {
                case LONG:
                    res.getLong();
                    break;
                    
                case ULONG:
                    res.getUnsignedLong();
                    break;
                    
                default:
                    res.getInt();
                    break;
                }
                fail("Must not execute");
            } catch (Exception e) {
                checkException(e, "Value out of range for '" + 
                                  (variation == IntegerVariations.ULONG ? "unsigned " :"") +
                                  (variation == IntegerVariations.INT ? "int" : "long") + "'"); 
            }
            assertTrue("cbor65", res.getBigInteger().toString().equals(value));
        } else {
            long v;
            switch (variation) {
            case LONG:
                v = res.getLong();
                break;
                
            case ULONG:
                v = res.getUnsignedLong();
                break;
                
            default:
                v = res.getInt();
                break;
            }
            assertTrue("Variations", v == new BigInteger(value).longValue());
        }
    }

    void bigIntegerTest(String value, String hex) throws Exception {
        byte[] cbor = new CBORInteger(new BigInteger(value)).encode();
        String calc = HexaDecimal.encode(cbor);
        assertTrue("big int=" + value + " c=" + calc + " h=" + hex,
                hex.equals(HexaDecimal.encode(cbor)));
        CBORObject decodedBig = CBORObject.decode(cbor);
        String decS = decodedBig.getBigInteger().toString();
        assertTrue("Big2 d=" + decS + " v=" + value, value.equals(decS));
    }

    void stringTest(String string, String hex) throws Exception {
        byte[] cbor = new CBORTextString(string).encode();
        String calc = HexaDecimal.encode(cbor);
        assertTrue("string=" + string + " c=" + calc + " h=" + hex, hex.equals(calc));
        assertTrue("string 2", CBORObject.decode(cbor).toString().equals("\"" + string + "\""));
    }

    void arrayTest(CBORArray cborArray, String hex) throws Exception {
        byte[] cbor = cborArray.encode();
        String calc = HexaDecimal.encode(cbor);
        assertTrue(" c=" + calc + " h=" + hex, hex.equals(calc));
        assertTrue("arr", CBORObject.decode(cbor).toString().equals(cborArray.toString()));
    }

    void unsupportedTag(String hex) {
        try {
            parseCborHex(hex);
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "Unsupported tag: " + hex.substring(0, 2).toLowerCase());
        }
    }
    
    void floatTest(String asText, String hex) {
        floatTest(asText, hex, 0);
    }
    void floatTest(String asText, String hex, int mustFail) {
        double v = Double.valueOf(asText);
        try {
            CBORObject cborObject = parseCborHex(hex);
            assertFalse("Double should fail", mustFail == 1);
            Double d = cborObject.getFloatingPoint();
            assertTrue("Equal d=" + d + " v=" + v, (d.compareTo(v)) == 0 ^ (mustFail != 0));
        } catch (Exception e) {
            assertTrue("Ok fail", mustFail != 0);
            checkException(e, "Non-deterministic encoding of floating point value");
        }
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
                "[1, [2, 3], [4, 5]]");
        binaryCompare(cborArray,"8301820203820405");

        cborArray = new CBORArray()
            .addObject(new CBORInteger(1))
            .addObject(new CBORMap()
                .setObject("best", new CBORInteger(2))
                .setObject("best2", new CBORInteger(3))
                .setObject("another", new CBORInteger(4)))
            .addObject(new CBORArray()
                .addObject(new CBORInteger(5))
                .addObject(new CBORInteger(6)));
        textCompare(cborArray,
                "[1, {\n  \"best\": 2,\n  \"best2\": 3,\n  \"another\": 4\n}, [5, 6]]");
        binaryCompare(cborArray,
                      "8301a36462657374026562657374320367616e6f7468657204820506");

        cborArray = new CBORArray()
            .addObject(new CBORInteger(1))
            .addObject(new CBORMap()
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
                "[1, {\n  8: 2,\n  58: 3,\n  -4: [true, false],\n  -90: null\n}, [4, 5]]");
        binaryCompare(cborArray,"8301a40802183a032382f5f43859f6820405");
        
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
        integerTest(-1,                  false, true,     "3bffffffffffffffff");
        
        integerTest("18446744073709551615", IntegerVariations.ULONG, false);
        integerTest("0", IntegerVariations.ULONG, false);
        integerTest("-1", IntegerVariations.ULONG, true);

        integerTest("-2147483648", IntegerVariations.INT, false);
        integerTest("-2147483649", IntegerVariations.INT, true);
        integerTest("2147483647", IntegerVariations.INT, false);
        integerTest("2147483648", IntegerVariations.INT, true);

        integerTest("-9223372036854775808", IntegerVariations.LONG, false);
        integerTest("-9223372036854775809", IntegerVariations.LONG, true);
        integerTest("9223372036854775807", IntegerVariations.LONG, false);
        integerTest("9223372036854775808", IntegerVariations.LONG, true);
        integerTest("-18446744073709551616", IntegerVariations.LONG, true);
        integerTest("-18446744073709551617", IntegerVariations.LONG, true);
        integerTest("18446744073709551616", IntegerVariations.LONG, true);
        
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
                .addObject(new CBORInteger(1))
                .addObject(new CBORInteger(2))
                .addObject(new CBORInteger(3)), "83010203");
        
//        unsupportedTag("C07819323032312D30352D30315430363A33373A35352B30313A3030");
        unsupportedTag("1C");
        
        // These numbers are supposed to be tie-breakers...
        floatTest("10.55999755859375",          "FA4128F5C0");
        floatTest("-1.401298464324817e-45",     "FA80000001");
        floatTest("-9.183549615799121e-41",     "FA80010000");
        floatTest("-1.8367099231598242e-40",    "FA80020000");
        floatTest("-3.6734198463196485e-40",    "FA80040000");
        floatTest("-7.346839692639297e-40",     "FA80080000");
        floatTest("-1.4693679385278594e-39",    "FA80100000");
        floatTest("-2.938735877055719e-39",     "FA80200000");
        floatTest("-5.877471754111438e-39",     "FA80400000");
        floatTest("-1.1754943508222875e-38",    "FA80800000");
        floatTest("-5.9604644775390625e-8",     "F98001");

        floatTest("-2.9387358770557184e-39",    "FBB7EFFFFFFFFFFFFF");
        floatTest("-2.9387358770557188e-39",    "FA80200000");

        floatTest("-5.8774717541114375e-39",    "FA80400000");
        floatTest("-1.1754943508222875e-38",    "FA80800000");
        floatTest("-3.1691265005705735e+29",    "FAF0800000");
        floatTest("-2.076918743413931e+34",     "FAF8800000");
        floatTest("-5.3169119831396635e+36",    "FAFC800000");
        floatTest("-2.1267647932558654e+37",    "FAFD800000");
        
        floatTest("3.4028234663852886e+38",     "FA7F7FFFFF");
        floatTest("3.4028234663852889e+38",     "FB47EFFFFFE0000001");

        floatTest("-8.507059173023462e+37",     "FAFE800000");
        floatTest("-3.090948894593554e+30",     "FAF21C0D94");
        floatTest("10.559999942779541",         "FB40251EB850000000");
        floatTest("10.559998512268066",         "FA4128F5C1");
        floatTest("1.0e+48",                    "FB49E5E531A0A1C873");
        floatTest("18440.0",                    "FA46901000");
        floatTest("18448.0",                    "F97481");
        floatTest("3.0517578125e-5",            "F90200");
        floatTest("3.057718276977539e-5",       "F90201");
        floatTest("6.097555160522461e-5",       "F903FF");
        floatTest("3.0547380447387695e-5",      "FA38002000");
        floatTest("3.0584633350372314e-5",      "FA38004800");
        floatTest("5.9604644775390625e-8",      "F90001");
        floatTest("5.960465188081798e-8",       "FA33800001");
        
        floatTest("65504.0",                    "F97BFF");
        floatTest("65504.00390625",             "FA477FE001");
        floatTest("65505.0",                    "FA477FE100");

        floatTest("65536.0",                    "FA47800000");
        floatTest("NaN",                        "F97E00");
        floatTest("Infinity",                   "F97C00");
        floatTest("-Infinity",                  "F9FC00");
        floatTest("0.0",                        "F90000");
        floatTest("-0.0",                       "F98000");
        
        floatTest("NaN",                        "FA80000000",           1);
        floatTest("NaN",                        "FB8000000000000000",   1);
        floatTest("65504.00390625",             "F97BFF",               2);
        
        assertTrue("Tag", new CBORTaggedObject(5, new CBORTextString("hi"))
                        .equals(parseCborHex("C5626869")));
    }
 
    public static boolean compareKeyId(CBORObject keyId, CBORObject optionalKeyId) {
        if (optionalKeyId == null) {
            return false;
        }
        return keyId.equals(optionalKeyId);
    }
    
    class MapTest extends CBORMap {
        
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
    
    void sortingTest(String[] expectedOrder) throws Exception{
        MapTest m = new MapTest();
        m.insert(new CBORInteger(10))
         .insert(new CBORArray().addObject(new CBORInteger(100)))
         .insert(new CBORInteger(-1))
         .insert(new CBORBoolean(false))
         .insert(new CBORArray().addObject(new CBORInteger(-1)))
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
        sortingTest(RFC8949_SORTING);
    }

    @Test
    public void bufferTest() throws Exception {
        // To not "accidently" allocate potentially GBs of memory the
        // decoder uses a buffer scheme.
        // The assumption is that the receiver has already checked
        // that the CBOR code itself is within reason size-wise.
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
        CBORObject cbor = parseCborHex("8301a40802183a032382f5f43859f6820405");
        try {
            ((CBORArray) cbor).getObject(0).getMap();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "Is type: INTEGER, requested: MAP");
        }

        try {
            ((CBORArray) cbor).getObject(1).getMap().getObject(-91).getInt();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "Missing key: -91");
        }
 
        try {
            parseCborHex("C5626869").getTaggedObject(6);
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "Tag number mismatch, requested=6, actual=5");
        }

        assertTrue("v1", ((CBORArray) cbor).getObject(1).getMap().getObject(58).getInt() == 3);

    }

    @Test
    public void unreadElementTest() throws Exception {
        CBORObject unread = null;
        try {
            unread = parseCborHex("8301a40802183a032382f5f43859f6820405");
            ((CBORArray) unread).getObject(0).getInt();
            unread.checkForUnread();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Map key 8 of type=CBORInteger with value=2 was never read");
        }

        try {
            unread = parseCborHex("8301a40802183a032382f5f43859f6820405");
            unread = ((CBORArray) unread).getObject(1).getMap();
            ((CBORMap)unread).getObject(8).getInt();
            ((CBORMap)unread).getObject(58).getInt();
            ((CBORArray)((CBORMap)unread).getObject(-4)).getObject(0).getBoolean();
            unread.checkForUnread();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Array element of type=CBORBoolean with value=false was never read");
        }
        
        try {
            unread = parseCborHex("C5626869");
            unread = ((CBORTaggedObject) unread).getTaggedObject(5);
            unread.checkForUnread();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Data of type=CBORTextString with value=\"hi\" was never read");
        }
        unread.getTextString();
        unread.checkForUnread();
        
        /*
             .addObject(new CBORInteger(1))
            .addObject(new CBORMap()
                .setObject(8, new CBORInteger(2))
                .setObject(58, new CBORInteger(3))
                .setObject(-90, new CBORNull())
                .setObject(-4, new CBORArray()
                    .addObject(new CBORBoolean(true))
                    .addObject(new CBORBoolean(false))))
 */

        // If you just want to mark an item as "read" you can use scan();
        try {
            unread = parseCborHex("8301a40802183a032382f5f43859f6820405");
            unread = ((CBORArray) unread).getObject(1).getMap();
            ((CBORMap)unread).getObject(8).getInt();
            ((CBORMap)unread).getObject(58).getInt();
            ((CBORArray)((CBORMap)unread).getObject(-4)).getObject(0).scan();
            unread.checkForUnread();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Array element of type=CBORBoolean with value=false was never read");
        }

        // Getting an object without reading the value is considered as "unread".
        try {
            unread = parseCborHex("8301a40802183a032382f5f43859f6820405");
            unread = ((CBORArray) unread).getObject(1).getMap();
            ((CBORMap)unread).getObject(8).getInt();
            ((CBORMap)unread).getObject(58).getInt();
            ((CBORArray)((CBORMap)unread).getObject(-4)).getObject(0);
            unread.checkForUnread();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Array element of type=CBORBoolean with value=true was never read");
        }
        
        try {
            unread = parseCborHex("17");
            unread.checkForUnread();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Data of type=CBORInteger with value=23 was never read");
        }

        try {
            unread = parseCborHex("A107666D7964617461");
            unread.checkForUnread();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Map key 7 of type=CBORTextString with value=\"mydata\" was never read");
        }

        try {
            unread = parseCborHex("A0");
            unread.checkForUnread();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Data of type=CBORMap with value={} was never read");
        }
        unread.getMap().checkForUnread();

        try {
            unread = parseCborHex("80");
            unread.checkForUnread();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Data of type=CBORArray with value=[] was never read");
        }
        unread.getArray().checkForUnread();
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
        try {
            cborObject.getFloatingPoint();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Is type: INTEGER, requested: FLOATING_POINT");
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
        try {
            parseCborHex("a363666d74646e6f6e656761747453746d74a0686175746844617461590" +
                         "104292aad5fe5a8dc9a56429b2b0864f69124d11d9616ba8372e0c00215" +
                         "337be5bd410000000000000000000000000000000000000202d4db1c");
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
                "Non-deterministic encoding of N");
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
        
        try {
            parseCborHex("A204616B026166");
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Non-deterministic sort order for map key: 2");
        }
        
        for (String value : new String[]{"1B8000000000000000", 
                                         "1B0001000000000000",
                                         "FB6950B8E0ACAC4EAF",
                                         "1A80000000",
                                         "1A00010000",
                                         "198000",
                                         "190100",
                                         "390100",
                                         "1880",
                                         "1818",
                                         "3818",
                                         "38FF",
                                         "F97C00",
                                         "F90000",
                                         "F98000",
                                         "17",
                                         "01",
                                         "00",
                                         "20",
                                         "37"}) {
            parseCborHex(value);
        }
        for (String value : new String[]{"1B00000000FFFFFFFF",
                                         "1B0000000080000000",
                                         "FB7FF8000000000000",
                                         "FB0000000000000000",
                                         "FB8000000000000000",
                                         "1A0000FFFF",
                                         "1A00008000",
                                         "1900FF",
                                         "190080",
                                         "3900FF",
                                         "390080",
                                         "1800",
                                         "1801",
                                         "1817",
                                         "3801",
                                         "3817",
                                         "F97C01"}) {
            try {
                parseCborHex(value);
                fail("must not execute");
            } catch (Exception e) {
                checkException(e, 
                        e.getMessage().contains("float") ?
                    "Non-deterministic encoding of floating point value, tag:"
                                                         :
                    "Non-deterministic encoding of N");
            }
        }
    }
    
    CBORObject createDataToBeSigned() throws IOException {
        return new CBORMap()
        .setObject(1, new CBORMap()
                .setObject(1, new CBORTextString("Space Shop"))
                .setObject(2, new CBORTextString("100.00"))
                .setObject(3, new CBORTextString("EUR")))
            .setObject(2, new CBORTextString("spaceshop.com"))
            .setObject(3, new CBORTextString("FR7630002111110020050014382"))
            .setObject(4, new CBORTextString("https://europeanpaymentsinitiative.eu/fwp"))
            .setObject(5, new CBORTextString("62932"))
            .setObject(6, new CBORTextString("2021-05-03T09:50:08Z"));
    }
    
    void backAndForth(KeyPair keyPair) throws Exception {
        CBORObject cborPublicKey = CBORPublicKey.encode(keyPair.getPublic());
        PublicKey publicKey = CBORPublicKey.decode(cborPublicKey);
        assertTrue("PK" + cborPublicKey.toString(), publicKey.equals(keyPair.getPublic()));
    }
    
    CBORObject signAndVerify(CBORSigner signer, CBORValidator validator) 
            throws IOException, GeneralSecurityException {
        CBORObject tbs = createDataToBeSigned();
        signer.sign(7, tbs.getMap());
        byte[] sd = tbs.encode();
        CBORObject cborSd = CBORObject.decode(sd);
        return validator.validate(7, cborSd.getMap());
     }
  
    void hmacTest(final int size, final HmacAlgorithms algorithm) throws IOException,
                                                                         GeneralSecurityException {
        CBORObject tbs = createDataToBeSigned();
        new CBORHmacSigner(symmetricKeys.getValue(size), algorithm).sign(7, tbs.getMap());
        byte[] sd = tbs.encode();
        CBORObject cborSd = CBORObject.decode(sd);
        new CBORHmacValidator(symmetricKeys.getValue(size)).validate(7, cborSd.getMap());
        
        tbs = createDataToBeSigned();
         new CBORHmacSigner(new HmacSignerInterface() {

            @Override
            public byte[] signData(byte[] data) throws IOException, GeneralSecurityException {
                return algorithm.digest(symmetricKeys.getValue(size), data);
            }

            @Override
            public HmacAlgorithms getAlgorithm() throws IOException, GeneralSecurityException {
                return algorithm;
            }
            
        }).sign(7, tbs.getMap());
        sd = tbs.encode();
        cborSd = CBORObject.decode(sd);
        new CBORHmacValidator(symmetricKeys.getValue(size)).validate(7, cborSd.getMap());

        tbs = createDataToBeSigned();
        CBORObject keyId = new CBORTextString(symmetricKeys.getName(size));
        new CBORHmacSigner(symmetricKeys.getValue(size), algorithm).setKeyId(keyId)
            .sign(7, tbs.getMap()); 
        sd = tbs.encode();
        cborSd = CBORObject.decode(sd);
        new CBORHmacValidator(
            new CBORHmacValidator.KeyLocator() {

                @Override
                public byte[] locate(CBORObject optionalKeyId, HmacAlgorithms hmacAlgorithm)
                        throws IOException, GeneralSecurityException {
                    if (!compareKeyId(keyId, optionalKeyId)) {
                        throw new IOException("Unknown keyId");
                    }
                    if (!algorithm.equals(hmacAlgorithm)) {
                        throw new IOException("Algorithm error");
                    }
                    return symmetricKeys.getValue(size);
                }
                
            }).validate(7, cborSd.getMap());
    }

    @Test
    public void signatureTest() throws Exception {
  
        backAndForth(p256);
        backAndForth(r2048);
        backAndForth(x448);
        backAndForth(x25519);
        backAndForth(ed448);
        backAndForth(ed25519);
        
        signAndVerify(new CBORAsymKeySigner(p256.getPrivate()), 
                      new CBORAsymKeyValidator(p256.getPublic()));

        signAndVerify(new CBORAsymKeySigner(p256.getPrivate()).setPublicKey(p256.getPublic()), 
                      new CBORAsymKeyValidator(p256.getPublic()));

        signAndVerify(new CBORAsymKeySigner(ed25519.getPrivate()).setPublicKey(ed25519.getPublic()), 
                      new CBORAsymKeyValidator(ed25519.getPublic()));

        signAndVerify(new CBORAsymKeySigner(r2048.getPrivate()).setPublicKey(r2048.getPublic()), 
                      new CBORAsymKeyValidator(r2048.getPublic()));

        signAndVerify(new CBORAsymKeySigner(p256.getPrivate()), 
                      new CBORAsymKeyValidator(new CBORAsymKeyValidator.KeyLocator() {
                
                @Override
                public PublicKey locate(PublicKey optionalPublicKey, 
                                        CBORObject optionalKeyId,
                                        AsymSignatureAlgorithms signatureAlgorithm)
                        throws IOException, GeneralSecurityException {
                    return p256.getPublic();
                }
            }));

        signAndVerify(new CBORAsymKeySigner(p256.getPrivate()), 
            new CBORAsymKeyValidator(new CBORAsymKeyValidator.KeyLocator() {
                
                @Override
                public PublicKey locate(PublicKey optionalPublicKey, 
                                        CBORObject optionalKeyId,
                                        AsymSignatureAlgorithms signatureAlgorithm)
                        throws IOException, GeneralSecurityException {
                    assertTrue("public", optionalPublicKey == null);
                    assertTrue("keyId", optionalKeyId == null);
                    assertTrue("alg", AsymSignatureAlgorithms.ECDSA_SHA256.equals(
                            signatureAlgorithm));
                    return p256.getPublic();
                }
            }));

        signAndVerify(new CBORAsymKeySigner(p256.getPrivate()).setKeyId(keyIdP256), 
            new CBORAsymKeyValidator(new CBORAsymKeyValidator.KeyLocator() {
                
                @Override
                public PublicKey locate(PublicKey optionalPublicKey, 
                                        CBORObject optionalKeyId,
                                        AsymSignatureAlgorithms signatureAlgorithm)
                        throws IOException, GeneralSecurityException {
                    return compareKeyId(keyIdP256, optionalKeyId) ? 
                                                 p256.getPublic() : p256_2.getPublic();
                }

            }));

        signAndVerify(new CBORX509Signer(p256.getPrivate(), p256CertPath),
            new CBORX509Validator(new CBORX509Validator.SignatureParameters() {

                @Override
                public void check(X509Certificate[] certificatePath,
                                  AsymSignatureAlgorithms signatureAlgorithm)
                        throws IOException, GeneralSecurityException {
                }

            }));

        signAndVerify(new CBORX509Signer(new X509SignerInterface() {

                @Override
                public byte[] signData(byte[] data)  throws IOException, GeneralSecurityException {
                    return new SignatureWrapper(AsymSignatureAlgorithms.ECDSA_SHA256, p256.getPrivate())
                            .update(data)
                            .sign();                    }
                
                @Override
                public AsymSignatureAlgorithms getAlgorithm() {
                    return AsymSignatureAlgorithms.ECDSA_SHA256;
                }
    
                @Override
                public X509Certificate[] getCertificatePath()
                        throws IOException, GeneralSecurityException {
                    return p256CertPath;
                }
                
            }), new CBORX509Validator(new CBORX509Validator.SignatureParameters() {

                @Override
                public void check(X509Certificate[] certificatePath,
                                  AsymSignatureAlgorithms signatureAlgorithm)
                        throws IOException, GeneralSecurityException {
                }

            }));
        
        try {
            signAndVerify(new CBORX509Signer(new X509SignerInterface() {
    
                    @Override
                    public byte[] signData(byte[] data)  throws IOException, GeneralSecurityException {
                        return new SignatureWrapper(AsymSignatureAlgorithms.ECDSA_SHA256, p256.getPrivate())
                                .update(data)
                                .sign();                    }
                    
                    @Override
                    public AsymSignatureAlgorithms getAlgorithm() {
                        return AsymSignatureAlgorithms.ECDSA_SHA384;
                    }
        
                    @Override
                    public X509Certificate[] getCertificatePath()
                            throws IOException, GeneralSecurityException {
                        return p256CertPath;
                    }
                    
                }), new CBORX509Validator(new CBORX509Validator.SignatureParameters() {
    
                    @Override
                    public void check(X509Certificate[] certificatePath,
                                      AsymSignatureAlgorithms signatureAlgorithm)
                            throws IOException, GeneralSecurityException {
                    }
    
                }));
            fail("Must not execute");
        } catch (Exception e) {
        }

        try {
            signAndVerify(new CBORX509Signer(p256.getPrivate(), p256CertPath).setKeyId(keyId),
                new CBORX509Validator(new CBORX509Validator.SignatureParameters() {
    
                    @Override
                    public void check(X509Certificate[] certificatePath,
                                      AsymSignatureAlgorithms signatureAlgorithm)
                            throws IOException, GeneralSecurityException {
                    }
    
                }));
            fail("Must not execute");
        } catch (Exception e) {
            checkException(e, CBORSigner.STDERR_KEY_ID_PUBLIC);
        }
        
        try {
            signAndVerify(new CBORX509Signer(p256_2.getPrivate(), p256CertPath),
                new CBORX509Validator(new CBORX509Validator.SignatureParameters() {

                    @Override
                    public void check(X509Certificate[] certificatePath,
                                      AsymSignatureAlgorithms signatureAlgorithm)
                            throws IOException, GeneralSecurityException {
                    }

                }));
            fail("Must not execute");
        } catch (Exception e) {
            // Deep errors are not checked for exact text
        }
        
        signAndVerify(new CBORAsymKeySigner(p256.getPrivate()).setPublicKey(p256.getPublic()), 
            new CBORAsymKeyValidator(new CBORAsymKeyValidator.KeyLocator() {
                
                @Override
                public PublicKey locate(PublicKey optionalPublicKey, 
                                        CBORObject optionalKeyId,
                                        AsymSignatureAlgorithms signatureAlgorithm)
                        throws IOException, GeneralSecurityException {
                    assertTrue("pk", p256.getPublic().equals(optionalPublicKey));
                    return optionalPublicKey;
                }
            }));

        try {
            signAndVerify(new CBORAsymKeySigner(p256.getPrivate()), 
                new CBORAsymKeyValidator(new CBORAsymKeyValidator.KeyLocator() {
                    
                    @Override
                    public PublicKey locate(PublicKey optionalPublicKey, 
                                            CBORObject optionalKeyId,
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
            signAndVerify(new CBORAsymKeySigner(p256.getPrivate())
                    .setAlgorithm(AsymSignatureAlgorithms.ED25519)
                    .setPublicKey(p256.getPublic()), 
                    new CBORAsymKeyValidator(p256.getPublic()));
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Supplied key (NIST_P_256) is incompatible with specified algorithm (ED25519)");
        }
        
        try {
            signAndVerify(new CBORAsymKeySigner(p256.getPrivate()).setPublicKey(p256.getPublic()), 
                    new CBORAsymKeyValidator(p256_2.getPublic()));
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "Public keys not identical");
        }

        try {
            new CBORAsymKeySigner(p256.getPrivate())
                .setPublicKey(p256.getPublic())
                .setKeyId(keyId)
                .sign(7, createDataToBeSigned().getMap()); 
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, CBORSigner.STDERR_KEY_ID_PUBLIC);
        }

        // HMAC signatures
        hmacTest(256, HmacAlgorithms.HMAC_SHA256);
        hmacTest(384, HmacAlgorithms.HMAC_SHA384);
        hmacTest(512, HmacAlgorithms.HMAC_SHA512);
        
        try {
            signAndVerify(new CBORAsymKeySigner(p256.getPrivate()), 
                    new CBORHmacValidator(new byte[] {9}));
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "Unknown COSE HMAC algorithm: -7");
        }
        
        try {
            signAndVerify(new CBORAsymKeySigner(p256.getPrivate()), 
                    new CBORAsymKeyValidator(ed25519.getPublic()));
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "Algorithm ECDSA_SHA256 does not match key type ED25519");
        }
        
        try {
            signAndVerify(new CBORAsymKeySigner(p256.getPrivate()), 
                new CBORAsymKeyValidator(new CBORAsymKeyValidator.KeyLocator() {
                    
                    @Override
                    public PublicKey locate(PublicKey optionalPublicKey, 
                                            CBORObject optionalKeyId,
                                            AsymSignatureAlgorithms signatureAlgorithm)
                            throws IOException, GeneralSecurityException {
                        if (compareKeyId(new CBORTextString("otherkey"), optionalKeyId)) {
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

    void enumerateEncryptions(KeyEncryptionAlgorithms[] keas,
                              KeyPair[] keyPairs) throws Exception {
        for (KeyEncryptionAlgorithms kea : keas) {
            for (ContentEncryptionAlgorithms cea : ContentEncryptionAlgorithms.values()) {
                for (KeyPair keyPair : keyPairs) {
                    CBORAsymKeyEncrypter encrypter = 
                            new CBORAsymKeyEncrypter(keyPair.getPublic(),
                                                     kea,
                                                     cea); 
                    byte[] encrypted = encrypter.encrypt(dataToEncrypt).encode();
                    assertTrue("enc/dec", 
                            ArrayUtil.compare(new CBORAsymKeyDecrypter(
                                    keyPair.getPrivate()).decrypt(encrypted),
                                    dataToEncrypt));
                }
            }
        }
    }

    void enumerateEncryptions(int[] keys)
            throws Exception {
        for (ContentEncryptionAlgorithms cea : ContentEncryptionAlgorithms.values()) {
            for (int key : keys) {
                byte[] secretKey = symmetricKeys.getValue(key);
                boolean ok = cea.getKeyLength() == secretKey.length;
                try {
                    CBORSymKeyEncrypter encrypter = new CBORSymKeyEncrypter(secretKey, cea);
                    byte[] encrypted = encrypter.encrypt(dataToEncrypt).encode();
                    assertTrue("enc/dec",
                            ArrayUtil.compare(
                                    new CBORSymKeyDecrypter(secretKey).decrypt(encrypted),
                                    dataToEncrypt));
                    assertTrue("Keysize1", ok);
                } catch (Exception e) {
                    assertTrue("Keysize2", !ok);
                }
            }
        }
    }

    @Test
    public void encryptionTest() throws Exception {
        
        // ECDH
        enumerateEncryptions(new KeyEncryptionAlgorithms[]
                                {KeyEncryptionAlgorithms.ECDH_ES,
                                 KeyEncryptionAlgorithms.ECDH_ES_A128KW,
                                 KeyEncryptionAlgorithms.ECDH_ES_A192KW,
                                 KeyEncryptionAlgorithms.ECDH_ES_A256KW},
                             new KeyPair[] {p256, p521, x25519, x448});
        
        // RSA
        enumerateEncryptions(new KeyEncryptionAlgorithms[]
                                {KeyEncryptionAlgorithms.RSA_OAEP,
                                 KeyEncryptionAlgorithms.RSA_OAEP_256},
                             new KeyPair[] {r2048});
        
        // Symmetric
        enumerateEncryptions(new int[] {128, 384, 256, 512});
        
        CBORAsymKeyEncrypter p256Encrypter = 
                new CBORAsymKeyEncrypter(p256.getPublic(),
                                         KeyEncryptionAlgorithms.ECDH_ES,
                                         ContentEncryptionAlgorithms.A256GCM);
        byte[] p256Encrypted = p256Encrypter.encrypt(dataToEncrypt).encode();
        assertTrue("enc/dec", 
                ArrayUtil.compare(new CBORAsymKeyDecrypter(
                        p256.getPrivate()).decrypt(p256Encrypted),
                        dataToEncrypt));
        p256Encrypter.setKeyId(keyId);
        byte[] p256EncryptedKeyId = p256Encrypter.encrypt(dataToEncrypt).encode();
        assertTrue("enc/dec", 
                ArrayUtil.compare(new CBORAsymKeyDecrypter(
                        p256.getPrivate()).decrypt(p256EncryptedKeyId),
                        dataToEncrypt));
        assertTrue("enc/dec", 
                ArrayUtil.compare(new CBORAsymKeyDecrypter(
                    new CBORAsymKeyDecrypter.KeyLocator() {
                        
                        @Override
                        public PrivateKey locate(
                                PublicKey optionalPublicKey,
                                CBORObject optionalKeyId,
                                ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                                KeyEncryptionAlgorithms keyEncryptionAlgorithm)
                                throws IOException, GeneralSecurityException {
                            return compareKeyId(keyId, optionalKeyId) ? p256.getPrivate() : null;
                        }

                    }).decrypt(p256EncryptedKeyId),
                    dataToEncrypt));
        try {
            new CBORAsymKeyEncrypter(p256.getPublic(),
                                     KeyEncryptionAlgorithms.ECDH_ES,
                                     ContentEncryptionAlgorithms.A256GCM)
                                         .setPublicKeyOption(true)
                                         .setKeyId(keyId).encrypt(dataToEncrypt);
            fail("must not run");
        } catch (Exception e) {
            checkException(e, CBORSigner.STDERR_KEY_ID_PUBLIC);
        }
        try {
            new CBORAsymKeyDecrypter(p256_2.getPrivate()).decrypt(p256Encrypted);
            fail("must not run");
        } catch (Exception e) {
            // No check here because it comes from the deep...
        }
        try {
            new CBORAsymKeyDecrypter(
                        p256.getPrivate()).decrypt(
                            CBORObject.decode(
                                    p256Encrypted).getMap().setObject(-2, new CBORInteger(5)).encode());
            fail("must not run");
        } catch (Exception e) {
            checkException(e, "Map key -2 of type=CBORInteger with value=5 was never read");
        }
        try {
            new CBORAsymKeyDecrypter(
                        p256.getPrivate()).decrypt(
                            CBORObject.decode(
                                    p256Encrypted).getMap()
                            .getObject(KEY_ENCRYPTION_LABEL)
                            .getMap().removeObject(ALGORITHM_LABEL).encode());
            fail("must not run");
        } catch (Exception e) {
            checkException(e, "Missing key: 1");
        }
        byte[] a256Encrypted = new CBORSymKeyEncrypter(symmetricKeys.getValue(256),
                                            ContentEncryptionAlgorithms.A256GCM)
                                                .encrypt(dataToEncrypt).encode();
        
        CBORSymKeyDecrypter a256Decrypter = new CBORSymKeyDecrypter(symmetricKeys.getValue(256));
        assertTrue("enc/dec", 
                ArrayUtil.compare(a256Decrypter.decrypt(a256Encrypted),
                        dataToEncrypt));
        
        try {
            a256Decrypter.decrypt(CBORObject.decode(
                a256Encrypted).getMap().setObject(KEY_ENCRYPTION_LABEL, 
                        new CBORMap().setObject(ALGORITHM_LABEL,
                                new CBORInteger(600))).encode());
            fail("must not run");
        } catch (Exception e) {
            checkException(e, "Map key 1 of type=CBORInteger with value=600 was never read");
        }
    }
    
    byte[] getBinaryFromHex(String hex) throws Exception {
        if (hex.length() == 0) {
            return new byte[0];
        }
        return HexaDecimal.decode(hex);
    }
    
    void hmacKdfRun(String ikmHex,
                    String saltHex,
                    String infoHex, 
                    int keyLen, 
                    String okmHex) throws Exception {
        assertTrue("KDF",
                HexaDecimal.encode(
                        EncryptionCore.hmacKdf(getBinaryFromHex(ikmHex),
                                               getBinaryFromHex(saltHex),
                                               getBinaryFromHex(infoHex),
                                               keyLen)).equals(okmHex));
    }
    
    @Test
    public void hmacKdfTest() throws Exception {

        // From appendix A of RFC 5869
        
        // A.1
        hmacKdfRun("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                   "000102030405060708090a0b0c",
                   "f0f1f2f3f4f5f6f7f8f9",
                   42,
                   "3cb25f25faacd57a90434f64d0362f2a" +
                      "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
                      "34007208d5b887185865");

        // A.2
        hmacKdfRun("000102030405060708090a0b0c0d0e0f" +
                     "101112131415161718191a1b1c1d1e1f" +
                     "202122232425262728292a2b2c2d2e2f" +
                     "303132333435363738393a3b3c3d3e3f" +
                     "404142434445464748494a4b4c4d4e4f",
                   "606162636465666768696a6b6c6d6e6f" +
                     "707172737475767778797a7b7c7d7e7f" +
                     "808182838485868788898a8b8c8d8e8f" +
                     "909192939495969798999a9b9c9d9e9f" +
                     "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                   "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
                     "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
                     "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
                     "e0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
                     "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                   82,
                   "b11e398dc80327a1c8e7f78c596a4934" +
                     "4f012eda2d4efad8a050cc4c19afa97c" +
                     "59045a99cac7827271cb41c65e590e09" +
                     "da3275600c2f09b8367793a9aca3db71" +
                     "cc30c58179ec3e87c14c01d5c1f3434f" +
                     "1d87");

        // A.3
        hmacKdfRun("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                   "",
                   "",
                   42,
                   "8da4e775a563c18f715f802a063c5a31" +
                      "b8a11f5c5ee1879ec3454e5f3c738d2d" +
                      "9d201395faa4b61a96c8");       
    }

    void parseStrangeCborHex(String hexInput,
                             String hexExpectedResult,
                             boolean ignoreAdditionalData, 
                             boolean ignoreKeySortingOrder) throws IOException {
        String result = HexaDecimal.encode(
                CBORObject.decodeWithOptions(HexaDecimal.decode(hexInput),
                                             ignoreAdditionalData,
                                             ignoreKeySortingOrder).encode()).toUpperCase();
        assertTrue("Strange=" + result, hexExpectedResult.equals(result));
    }

    @Test
    public void decodeWithOptions() throws Exception {
        parseStrangeCborHex("A204616B026166", "A202616604616B", false, true);
        parseStrangeCborHex("A202616604616B01", "A202616604616B", true, false);
    }


    private String serializeJson(String[] jsonTokens, boolean addWhiteSpace) {
        StringBuilder s = new StringBuilder();
        for (String jsonToken : jsonTokens) {
            if (addWhiteSpace) {
                s.append(' ');
            }
            s.append(jsonToken);
        }
        if (addWhiteSpace) {
            s.append(' ');
        }
        return s.toString();
    }
    
    private CBORObject serializeJson(String[] jsonTokens) throws Exception {
        CBORObject one = CBORFromJSON.convert(serializeJson(jsonTokens, false));
        assertTrue("jsonCompp", one.equals(CBORFromJSON.convert(serializeJson(jsonTokens, true))));
        return one;
    }
    
    private CBORObject serializeJson(String jsonToken) throws Exception {
        return serializeJson(new String[] {jsonToken});
    }
    
    private void conversionError(String badJson) throws Exception {
        try {
            CBORFromJSON.convert(badJson);
            fail("Should fail on: " + badJson);
        } catch (Exception e) {
        }
    }
    
    @Test
    public void json2CborConversions() throws Exception {
        String[] jsonTokens = new String[] {
                "{", "\"lab\"", ":", "true", "}"
        };
        CBORMap cborMap = new CBORMap()
            .setObject("lab", new CBORBoolean(true));
        assertTrue("json", cborMap.equals(serializeJson(jsonTokens)));
        
        assertTrue("json", new CBORMap().equals(serializeJson(new String[] {"{","}"})));
        
        jsonTokens = new String[] {
                "{", "\"lab\"", ":", "true", "," ,"\"j\"",":", "2000", "}"
        };
        cborMap = new CBORMap()
            .setObject("lab", new CBORBoolean(true))
            .setObject("j", new CBORInteger(2000));
        assertTrue("json", cborMap.equals(serializeJson(jsonTokens)));
        
        assertTrue("json", new CBORArray().equals(serializeJson(new String[] {"[","]"})));
               
        assertTrue("json", new CBORTextString("hi").equals(serializeJson("\"hi\"")));
        assertTrue("json", new CBORTextString("").equals(serializeJson("\"\"")));
        assertTrue("json", new CBORTextString("\u20ac$\n\b\r\t\"\\ ").equals(serializeJson(
                                              "\"\\u20ac$\\u000a\\b\\r\\t\\\"\\\\ \"")));
        assertTrue("json", new CBORTextString("\u0123\u4567\u89ab\ucdef\uABCD\uEF00").equals(serializeJson(
                                              "\"\\u0123\\u4567\\u89ab\\ucdef\\uABCD\\uEF00\"")));
        assertTrue("json", new CBORBoolean(true).equals(serializeJson("true")));
        assertTrue("json", new CBORBoolean(false).equals(serializeJson("false")));
        assertTrue("json", new CBORNull().equals(serializeJson("null")));
        assertTrue("json", new CBORInteger(-234).equals(serializeJson("-234")));
        assertTrue("json", new CBORInteger(234).equals(serializeJson("234")));
        assertTrue("json", new CBORInteger(1).equals(serializeJson("1")));
        assertTrue("json", new CBORInteger(987654321).equals(serializeJson("0987654321")));
        assertTrue("json", new CBORInteger(new BigInteger("9007199254740992")).equals(serializeJson(
                                                          "9007199254740992")));
        
        CBORArray cborArray = new CBORArray()
            .addObject(new CBORTextString("hi"));
        assertTrue("json", cborArray.equals(serializeJson(new String[] {"[","\"hi\"","]"})));
        cborArray.addObject(new CBORMap())
                 .addObject(new CBORInteger(4));
        assertTrue("json", cborArray.equals(serializeJson(new String[] {
                "[","\"hi\"",",","{","}",",","4","]"})));
        cborArray.getObject(1).getMap().setObject("kurt", new CBORTextString("murt"));
        assertTrue("json", cborArray.equals(serializeJson(new String[] {
                "[","\"hi\"",",","{","\"kurt\"",":","\"murt\"","}",",","4","]"})));
        
        conversionError("");
        conversionError("k");
        conversionError("\"k");
        conversionError("\"\\k\"");
        conversionError("\"\\ufffl\"");
        conversionError("0y");
        conversionError("8.0");
        conversionError("0 8");
        conversionError("[");
        conversionError("[] 6");
        conversionError("9007199254740993");
        conversionError("[6,]");
        conversionError("{6:8}");
        conversionError("{\"6\":8,}");
        conversionError("{\"6\",8}");
        conversionError("{} 6");
    }
}
