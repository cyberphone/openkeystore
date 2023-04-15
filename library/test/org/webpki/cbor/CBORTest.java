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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.util.Locale;

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
import org.webpki.util.Base64URL;
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
        baseKey = System.clearProperty("test.keys") + File.separator;
        CustomCryptoProvider.forcedLoad(false);
        dataToEncrypt = "The quick brown fox jumps over the lazy bear".getBytes("utf-8");
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
        p256CertPath = PEMDecoder.getCertificatePath(ArrayUtil.readFile(baseKey +
                                                                        "p256certpath.pem"));
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
    
    enum IntegerVariations {
        LONG(CBORObject.STDERR_INCOMPATIBLE_LONG), 
        ULONG(CBORObject.STDERR_INCOMPATIBLE_UNSIGNED_LONG),
        INT(CBORObject.STDERR_INCOMPATIBLE_INT);
        
        String error;
        
        IntegerVariations(String error) {
            this.error = error;
        }
    };
    
    static CBORInteger SIGNATURE_LABEL = new CBORInteger(-1);
    
    static KeyPair readJwk(String keyType) throws Exception {
        JSONObjectReader jwkPlus = JSONParser.parse(
                ArrayUtil.readFile(baseKey + keyType + "privatekey.jwk"));
        // Note: The built-in JWK decoder does not accept "kid" since
        // it doesn't have a meaning in JSF or JEF. 
        keyId = new CBORString(jwkPlus.getString("kid"));
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

    void integerTest(long value, 
                     boolean forceUnsigned, 
                     boolean set, 
                     String hex) throws Exception {
        CBORObject cborObject = set ? 
                new CBORInteger(value, forceUnsigned) : new CBORInteger(value);
        byte[] cbor = cborObject.encode();
        String calc = HexaDecimal.encode(cbor);
        assertTrue("int=" + value + " c=" + calc + " h=" + hex, hex.equals(calc));
        CBORObject decodedInteger = CBORObject.decode(cbor);
        if (value != -1 || forceUnsigned) {
            long dv = forceUnsigned ? 
                    decodedInteger.getUnsignedLong()
                                    :
                    decodedInteger.getLong();
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
        BigInteger bigInteger = new BigInteger(value);
        CBORObject cborBigInteger = new CBORBigInteger(bigInteger);
        byte[] cbor = cborBigInteger.encode();
        CBORObject res = CBORObject.decode(cbor);
        assertTrue("int", res.equals(cborBigInteger));
        if (res.getType() == CBORTypes.INTEGER) {
            CBORInteger cborInteger = (CBORInteger)res;
            assertTrue("int", 
                       new CBORInteger(cborInteger.value, 
                                       cborInteger.unsigned).equals(cborBigInteger));
            if (bigInteger.compareTo(BigInteger.ZERO)< 0) {
                assertTrue("sint", 
                           new CBORInteger(~bigInteger.longValue(), 
                                           false).equals(cborBigInteger));
            } else {
                assertTrue("uint", 
                        new CBORInteger(bigInteger.longValue(), 
                                        true).equals(cborBigInteger));
            }
        }
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
                if (res.getType() == CBORTypes.INTEGER) {
                    checkException(e, variation.error); 
                }
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
        byte[] cbor = new CBORBigInteger(new BigInteger(value)).encode();
        String calc = HexaDecimal.encode(cbor);
        assertTrue("big int=" + value + " c=" + calc + " h=" + hex,
                hex.equals(HexaDecimal.encode(cbor)));
        CBORObject decodedBig = CBORObject.decode(cbor);
        String decS = decodedBig.getBigInteger().toString();
        assertTrue("Big2 d=" + decS + " v=" + value, value.equals(decS));
    }

    void stringTest(String string, String hex) throws Exception {
        byte[] cbor = new CBORString(string).encode();
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
            checkException(e, 
                           CBORObject.STDERR_UNSUPPORTED_TAG + hex.substring(0, 2).toLowerCase());
        }
    }
    
    void doubleTest(String asText, String hex) {
        doubleTest(asText, hex, 0);
    }
    void doubleTest(String asText, String hex, int mustFail) {
        double v = Double.valueOf(asText);
        try {
            CBORObject cborObject = parseCborHex(hex);
            int l;
            if (mustFail == 0) {
                switch (((CBORFloatingPoint) cborObject).getIeeeVariant()) {
                    case F16:
                        l = 3;
                        break;
                    case F32:
                        l = 5;
                        break;
                    default:
                        l = 9;
                        break;
                }
                assertTrue("ieee", l == cborObject.encode().length);
            }
            assertFalse("Double should fail", mustFail == 1);
            Double d = cborObject.getDouble();
            assertTrue("Equal d=" + d + " v=" + v, (d.compareTo(v)) == 0 ^ (mustFail != 0));
        } catch (Exception e) {
            assertTrue("Ok fail", mustFail != 0);
            checkException(e, CBORObject.STDERR_NON_DETERMINISTIC_FLOAT);
        }
    }
    
    void floatTest(String asText, String hex, boolean mustFail) throws IOException {
        double v = Double.valueOf(asText);
        CBORObject cborObject = parseCborHex(hex);
        try {
            float f = cborObject.getFloat();
            assertFalse("Should fail", mustFail);
            if (Float.isNaN(f) && Double.isNaN(v)) {
                return;
            }
            assertTrue("Comp", v == f);
        } catch (Exception e) {
            assertTrue("Ok fail", mustFail);
            checkException(e, CBORObject.STDERR_FLOAT_RANGE);
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
                .setObject(new CBORString("best"), new CBORInteger(2))
                .setObject(new CBORString("best2"), new CBORInteger(3))
                .setObject(new CBORString("another"), new CBORInteger(4)))
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
                .setObject(new CBORInteger(8), new CBORInteger(2))
                .setObject(new CBORInteger(58), new CBORInteger(3))
                .setObject(new CBORInteger(-90), new CBORNull())
                .setObject(new CBORInteger(-4), new CBORArray()
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
        integerTest("18446744073709551615", IntegerVariations.ULONG, false);
        integerTest("18446744073709551616", IntegerVariations.ULONG, true);
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
        doubleTest("10.55999755859375",          "FA4128F5C0");
        doubleTest("-1.401298464324817e-45",     "FA80000001");
        doubleTest("-9.183549615799121e-41",     "FA80010000");
        doubleTest("-1.8367099231598242e-40",    "FA80020000");
        doubleTest("-3.6734198463196485e-40",    "FA80040000");
        doubleTest("-7.346839692639297e-40",     "FA80080000");
        doubleTest("-1.4693679385278594e-39",    "FA80100000");
        doubleTest("-2.938735877055719e-39",     "FA80200000");
        doubleTest("-5.877471754111438e-39",     "FA80400000");
        doubleTest("-1.1754943508222875e-38",    "FA80800000");
        doubleTest("-5.9604644775390625e-8",     "F98001");

        doubleTest("-2.9387358770557184e-39",    "FBB7EFFFFFFFFFFFFF");
        doubleTest("-2.9387358770557188e-39",    "FA80200000");

        doubleTest("-5.8774717541114375e-39",    "FA80400000");
        doubleTest("-1.1754943508222875e-38",    "FA80800000");
        doubleTest("-3.1691265005705735e+29",    "FAF0800000");
        doubleTest("-2.076918743413931e+34",     "FAF8800000");
        doubleTest("-5.3169119831396635e+36",    "FAFC800000");
        doubleTest("-2.1267647932558654e+37",    "FAFD800000");
        
        doubleTest("3.4028234663852886e+38",     "FA7F7FFFFF");
        doubleTest("3.4028234663852889e+38",     "FB47EFFFFFE0000001");

        doubleTest("-8.507059173023462e+37",     "FAFE800000");
        doubleTest("-3.090948894593554e+30",     "FAF21C0D94");
        doubleTest("10.559999942779541",         "FB40251EB850000000");
        doubleTest("10.559998512268066",         "FA4128F5C1");
        doubleTest("1.0e+48",                    "FB49E5E531A0A1C873");
        doubleTest("18440.0",                    "FA46901000");
        doubleTest("18448.0",                    "F97481");
        doubleTest("3.0517578125e-5",            "F90200");
        doubleTest("3.057718276977539e-5",       "F90201");
        doubleTest("6.097555160522461e-5",       "F903FF");
        doubleTest("6.103515625e-5",             "F90400");
        doubleTest("3.0547380447387695e-5",      "FA38002000");
        doubleTest("3.0584633350372314e-5",      "FA38004800");
        doubleTest("5.9604644775390625e-8",      "F90001");
        doubleTest("5.960465188081798e-8",       "FA33800001");
        doubleTest("-5.9604644775390625e-8",     "F98001");
        doubleTest("-5.960465188081798e-8",      "FAB3800001");
        doubleTest("3.4028234663852886e+38",     "FA7F7FFFFF");
        doubleTest("3.402823466385289e+38",      "FB47EFFFFFE0000001");
        doubleTest("5.0e-324",                   "FB0000000000000001");
        
        doubleTest("65504.0",                    "F97BFF");
        doubleTest("65504.00390625",             "FA477FE001");
        doubleTest("-65504.00390625",            "FAC77FE001");
        doubleTest("65505.0",                    "FA477FE100");

        doubleTest("65536.0",                    "FA47800000");
        doubleTest("NaN",                        "F97E00");
        doubleTest("Infinity",                   "F97C00");
        doubleTest("-Infinity",                  "F9FC00");
        doubleTest("0.0",                        "F90000");
        doubleTest("-0.0",                       "F98000");
        
        doubleTest("NaN",                        "FA80000000",           1);
        doubleTest("NaN",                        "FB8000000000000000",   1);
        doubleTest("65504.00390625",             "F97BFF",               2);
        
        floatTest("NaN",                    "F97E00",             false);
        floatTest("0.0",                    "F90000",             false);
        floatTest("3.4028234663852886e+38", "FA7F7FFFFF",         false);
        floatTest("3.4028234663852889e+38", "FB47EFFFFFE0000001", true);
        
        assertTrue("Tag", new CBORTag(5, new CBORString("hi"))
                        .equals(parseCborHex("C5626869")));
        
        assertFalse("comp", parseCborHex("C5626869").equals(null));
        assertFalse("comp", parseCborHex("C5626869").equals("jj"));
        assertTrue("comp", parseCborHex("C5626869").equals(parseCborHex("C5626869")));
        
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
         .insert(new CBORString("aaa"))
         .insert(new CBORString("z"))
         .insert(new CBORString("aa"));
        assertTrue("size", m.size() == expectedOrder.length);
        while (m.size() > 0) {
            CBORObject removed = m.getKeys()[m.size() - 1];
            int i = 0;
            for (CBORObject key : m.getKeys()) {
                String expected = expectedOrder[i++];
                assertTrue("key=" + key + " exp=" + expected, key.toString().equals(expected));
            }
            m.removeObject(removed);
        }
    }
    
    @Test
    public void mapperTest() throws Exception {
        sortingTest(RFC8949_SORTING);
    }
    
    class StrangeReader extends InputStream {
        
        byte[] data;
        int position;
        
        StrangeReader(byte[] data) {
            this.data = data;
        }

        @Override
        public int read() throws IOException {
            assertTrue("pos", position <= data.length);
            int value = position == data.length ? -1 : data[position] & 0xff;
            position++;
            return value;
        }
        
        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int actual = 0;
            while (--len >= 0 && actual < 5) {
                int value = read();
                if (value < 0) {
                    return value;
                }
                b[off++] = (byte) value;
                actual++;
            }
            return actual;
        }
    }

    @Test
    public void bufferTest() throws Exception {
        byte[] cbor = HexaDecimal.decode(
   "782c74686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a792062656172");
        assertTrue("bt", 
                ArrayUtil.compare(cbor,
                          CBORObject.decode(
                                  new StrangeReader(cbor), false, false, false, null).encode()));

        assertTrue("bt", 
                ArrayUtil.compare(cbor,
                          CBORObject.decode(new StrangeReader(cbor), 
                                            false, false, false, cbor.length).encode()));
        try {
            CBORObject.decode(new ByteArrayInputStream(HexaDecimal.decode("7BFFFFFFFFFFFFFFFF00")), 
                              false, false, false, null);
            fail("Not valid");
        } catch (Exception e) {
            checkException(e, CBORObject.STDERR_N_RANGE_ERROR + "-1");
        }
        try {
            CBORObject.decode(new ByteArrayInputStream(HexaDecimal.decode("7AFFFFFFFF00")), 
                              false, false, false, null);
            fail("Not valid");
        } catch (Exception e) {
            checkException(e, CBORObject.STDERR_N_RANGE_ERROR + "4294967295");
        }
        try {
            CBORObject.decode(new ByteArrayInputStream(HexaDecimal.decode("797FFF00")), 
                              false, false, false, 100);
            fail("Not valid");
        } catch (Exception e) {
            checkException(e, CBORObject.STDERR_READING_LIMIT);
        }
        try {
            CBORObject.decode(new ByteArrayInputStream(HexaDecimal.decode("7A7FFFFFFF00")), 
                              false, false, false, null);
            fail("Not valid");
        } catch (Exception e) {
            checkException(e, CBORObject.STDERR_READING_LIMIT);
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
            ((CBORArray) cbor).getObject(1).getMap()
                    .getObject(new CBORInteger(-91)).getInt();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "Missing key: -91");
        }
 
        assertTrue("v1", ((CBORArray) cbor).getObject(1).getMap()
                .getObject(new CBORInteger(58)).getInt() == 3);

        assertTrue("tag5", parseCborHex("C5626869").getTag().getTagNumber() == 5);
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
                "Map key 8 with argument of type=INTEGER with value=2 was never read");
        }

        try {
            unread = parseCborHex("8301a40802183a032382f5f43859f6820405");
            unread = ((CBORArray) unread).getObject(1).getMap();
            ((CBORMap)unread).getObject(new CBORInteger(8)).getInt();
            ((CBORMap)unread).getObject(new CBORInteger(58)).getInt();
            ((CBORArray)((CBORMap)unread).getObject(new CBORInteger(-4))).getObject(0).getBoolean();
            unread.checkForUnread();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Array element of type=BOOLEAN with value=false was never read");
        }
        
        try {
            unread = parseCborHex("C5626869");
            unread = ((CBORTag) unread).getTag().getObject();
            unread.checkForUnread();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Data of type=TEXT_STRING with value=\"hi\" was never read");
        }
        unread.getString();
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
            ((CBORMap)unread).getObject(new CBORInteger(8)).getInt();
            ((CBORMap)unread).getObject(new CBORInteger(58)).getInt();
            ((CBORArray)((CBORMap)unread).getObject(new CBORInteger(-4))).getObject(0).scan();
            unread.checkForUnread();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Array element of type=BOOLEAN with value=false was never read");
        }

        // Getting an object without reading the value is considered as "unread".
        try {
            unread = parseCborHex("8301a40802183a032382f5f43859f6820405");
            unread = ((CBORArray) unread).getObject(1).getMap();
            ((CBORMap)unread).getObject(new CBORInteger(8)).getInt();
            ((CBORMap)unread).getObject(new CBORInteger(58)).getInt();
            ((CBORArray)((CBORMap)unread).getObject(new CBORInteger(-4))).getObject(0);
            unread.checkForUnread();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Array element of type=BOOLEAN with value=true was never read");
        }
        
        try {
            unread = parseCborHex("17");
            unread.checkForUnread();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Data of type=INTEGER with value=23 was never read");
        }

        try {
            unread = parseCborHex("A107666D7964617461");
            unread.checkForUnread();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Map key 7 with argument of type=TEXT_STRING with value=\"mydata\" was never read");
        }

        try {
            unread = parseCborHex("A0");
            unread.checkForUnread();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Data of type=MAP with value={} was never read");
        }
        unread.getMap().checkForUnread();

        try {
            unread = parseCborHex("80");
            unread.checkForUnread();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Data of type=ARRAY with value=[] was never read");
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
            cborObject.getBytes();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Is type: INTEGER, requested: BYTE_STRING");
        }
        try {
            cborObject.getDouble();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Is type: INTEGER, requested: FLOATING_POINT");
        }
        try {
            new CBORMap().setObject(null, new CBORInteger(1));
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, CBORObject.STDERR_ARGUMENT_IS_NULL);
        }
        try {
            new CBORMap().setObject(new CBORInteger(1), null);
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, CBORObject.STDERR_ARGUMENT_IS_NULL);
        }
        try {
            new CBORMap().getObject(null);
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, CBORObject.STDERR_ARGUMENT_IS_NULL);
        }
    }

    @Test
    public void endOfFileTest() throws Exception {
        try {
            parseCborHex("83");
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, CBORObject.STDERR_CBOR_EOF);
        }
        try {
            parseCborHex("a363666d74646e6f6e656761747453746d74a0686175746844617461590" +
                         "104292aad5fe5a8dc9a56429b2b0864f69124d11d9616ba8372e0c00215" +
                         "337be5bd410000000000000000000000000000000000000202d4db1c");
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, CBORObject.STDERR_READING_LIMIT);
        }
    }

    @Test
    public void deterministicEncodingTest() throws Exception {

        try {
            parseCborHex("3800");
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, CBORObject.STDERR_NON_DETERMINISTIC_CODING_OF_N);
        }

        try {
            parseCborHex("c24900ffffffffffffffff");
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, CBORObject.STDERR_LEADING_ZERO);
        }

        try {
            parseCborHex("c24101");
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, CBORObject.STDERR_NON_DETERMINISTIC_INT);
        }
        
        try {
            parseCborHex("A204616B026166");
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, CBORMap.STDERR_NON_DET_SORT_ORDER + "2");
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
                    CBORObject.STDERR_NON_DETERMINISTIC_FLOAT
                                                         :
                    CBORObject.STDERR_NON_DETERMINISTIC_CODING_OF_N);
            }
        }
    }
    
    CBORMap createDataToBeSigned() throws IOException {
        return new CBORMap()
        .setObject(new CBORInteger(1), new CBORMap()
                .setObject(new CBORInteger(1), new CBORString("Space Shop"))
                .setObject(new CBORInteger(2), new CBORString("100.00"))
                .setObject(new CBORInteger(3), new CBORString("EUR")))
            .setObject(new CBORInteger(2), new CBORString("spaceshop.com"))
            .setObject(new CBORInteger(3), new CBORString("FR7630002111110020050014382"))
            .setObject(new CBORInteger(4), new CBORString("https://europeanpaymentsinitiative.eu/fwp"))
            .setObject(new CBORInteger(5), new CBORString("62932"))
            .setObject(new CBORInteger(6), new CBORString("2021-05-03T09:50:08Z"));
    }
    
    void backAndForth(KeyPair keyPair) throws Exception {
        CBORObject cborPublicKey = CBORPublicKey.convert(keyPair.getPublic());
        PublicKey publicKey = CBORPublicKey.convert(cborPublicKey);
        assertTrue("PK" + cborPublicKey.toString(), publicKey.equals(keyPair.getPublic()));
    }
    
    CBORObject signAndVerify(CBORSigner signer, 
                             CBORValidator validator,
                             Long tagNumber,
                             String objectId) 
            throws IOException, GeneralSecurityException {
        CBORMap tbs = createDataToBeSigned();
        if (tagNumber != null) {
            signer.setIntercepter(new CBORCryptoUtils.Intercepter() {
                
                @Override
                public CBORObject wrap(CBORMap cborMap) {
                    return new CBORTag(tagNumber,
                            objectId == null ? tbs : new CBORArray()
                                    .addObject(new CBORString(objectId))
                                    .addObject(tbs));
                }
                
            });
            validator.setTagPolicy(CBORCryptoUtils.POLICY.MANDATORY, new CBORCryptoUtils.Collector() {
                
                @Override
                public void foundData(CBORObject objectOrNull)
                        throws IOException, GeneralSecurityException {
                    if (objectId == null) {
                        assertTrue("tagn", objectOrNull.getTag().getTagNumber() == tagNumber);
                    } else {
                        assertTrue("id", 
                                   objectOrNull.getTag()
                                       .getObject()
                                           .getArray()
                                               .getObject(0)
                                                   .getString().equals(objectId));
                        
                    }
                }
            });
        }

        CBORObject signedData = signer.sign(SIGNATURE_LABEL, tbs);
        byte[] sd = signedData.encode();
        CBORObject cborSd = CBORObject.decode(sd);
        return validator.validate(SIGNATURE_LABEL, cborSd);
     }

    CBORObject signAndVerify(CBORSigner signer, CBORValidator validator) 
            throws IOException, GeneralSecurityException {
        return signAndVerify(signer, validator, null, null);
    }

    void hmacTest(final int size, final HmacAlgorithms algorithm) throws IOException,
                                                                         GeneralSecurityException {
        CBORMap tbs = createDataToBeSigned();
        new CBORHmacSigner(symmetricKeys.getValue(size),
                           algorithm).sign(SIGNATURE_LABEL, tbs);
        byte[] sd = tbs.encode();
        CBORObject cborSd = CBORObject.decode(sd);
        new CBORHmacValidator(symmetricKeys.getValue(size)).validate(SIGNATURE_LABEL, cborSd);
        
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
            
        }).sign(SIGNATURE_LABEL, tbs);
        sd = tbs.encode();
        cborSd = CBORObject.decode(sd);
        new CBORHmacValidator(symmetricKeys.getValue(size)).validate(SIGNATURE_LABEL, cborSd);

        tbs = createDataToBeSigned();
        CBORObject keyId = new CBORString(symmetricKeys.getName(size));
        new CBORHmacSigner(symmetricKeys.getValue(size), algorithm).setKeyId(keyId)
            .sign(SIGNATURE_LABEL, tbs); 
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
                
            }).validate(SIGNATURE_LABEL, cborSd.getMap());
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

        signAndVerify(new CBORAsymKeySigner(r2048.getPrivate()).setPublicKey(r2048.getPublic()), 
                      new CBORAsymKeyValidator(r2048.getPublic()), 18l, null);

        signAndVerify(new CBORAsymKeySigner(r2048.getPrivate()).setPublicKey(r2048.getPublic()), 
                      new CBORAsymKeyValidator(r2048.getPublic()), 
                                               (long)CBORTag.RESERVED_TAG_COTX, 
                                               "https://example.com/myobject");

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
            new CBORX509Validator(new CBORX509Validator.Parameters() {

                @Override
                public void verify(X509Certificate[] certificatePath,
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
                
            }), new CBORX509Validator(new CBORX509Validator.Parameters() {

                @Override
                public void verify(X509Certificate[] certificatePath,
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
                    
                }), new CBORX509Validator(new CBORX509Validator.Parameters() {
    
                    @Override
                    public void verify(X509Certificate[] certificatePath,
                                      AsymSignatureAlgorithms signatureAlgorithm)
                            throws IOException, GeneralSecurityException {
                    }
    
                }));
            fail("Must not execute");
        } catch (Exception e) {
        }

        try {
            signAndVerify(new CBORX509Signer(p256.getPrivate(), p256CertPath).setKeyId(keyId),
                new CBORX509Validator(new CBORX509Validator.Parameters() {
    
                    @Override
                    public void verify(X509Certificate[] certificatePath,
                                      AsymSignatureAlgorithms signatureAlgorithm)
                            throws IOException, GeneralSecurityException {
                    }
    
                }));
            fail("Must not execute");
        } catch (Exception e) {
            checkException(e, CBORCryptoUtils.STDERR_KEY_ID_PUBLIC);
        }
        
        try {
            signAndVerify(new CBORX509Signer(p256_2.getPrivate(), p256CertPath),
                new CBORX509Validator(new CBORX509Validator.Parameters() {

                    @Override
                    public void verify(X509Certificate[] certificatePath,
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
            signAndVerify(new CBORAsymKeySigner(p256.getPrivate(), AsymSignatureAlgorithms.ED25519)
                    .setPublicKey(p256.getPublic()), 
                    new CBORAsymKeyValidator(p256.getPublic()));
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Supplied key (P_256) is incompatible with specified algorithm (ED25519)");
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
                .sign(SIGNATURE_LABEL, createDataToBeSigned().getMap()); 
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, CBORCryptoUtils.STDERR_KEY_ID_PUBLIC);
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
            checkException(e, "Supplied key (ED25519) is incompatible " +
                              "with specified algorithm (ECDSA_SHA256)");
        }
        
        try {
            signAndVerify(new CBORAsymKeySigner(p256.getPrivate()), 
                new CBORAsymKeyValidator(new CBORAsymKeyValidator.KeyLocator() {
                    
                    @Override
                    public PublicKey locate(PublicKey optionalPublicKey, 
                                            CBORObject optionalKeyId,
                                            AsymSignatureAlgorithms signatureAlgorithm)
                            throws IOException, GeneralSecurityException {
                        if (compareKeyId(new CBORString("otherkey"), optionalKeyId)) {
                            return p256_2.getPublic();
                        }
                        throw new IOException("KeyId = " + optionalKeyId);
                    }
                }));
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "KeyId = null");
        }
        
        String objectId = "https://example.com/myobject";
        
        // 2-dimensional tag
        CBORSigner tagSigner = new CBORAsymKeySigner(p256.getPrivate())
            .setIntercepter(new CBORCryptoUtils.Intercepter() {
                
                @Override
                public CBORObject wrap(CBORMap mapToSign) 
                        throws IOException, GeneralSecurityException {
                    return new CBORTag(objectId, mapToSign);
                }
            
        });
        
        CBORObject taggedSignature = tagSigner.sign(SIGNATURE_LABEL,
                                                    createDataToBeSigned());
        try {
            new CBORAsymKeyValidator(p256.getPublic()).validate(SIGNATURE_LABEL, taggedSignature);
            fail("must fail");
        } catch (Exception e) {
            checkException(e, "Tag encountered. Policy: FORBIDDEN");
        }
        new CBORAsymKeyValidator(p256.getPublic())
           .setTagPolicy(CBORCryptoUtils.POLICY.OPTIONAL, new CBORCryptoUtils.Collector() {

                @Override
                public void foundData(CBORObject objectOrNull)
                        throws IOException, GeneralSecurityException {
                    assertTrue("id", 
                               objectOrNull.getTag()
                                   .getObject()
                                       .getArray()
                                           .getObject(0)
                                               .getString().equals(objectId));
                }
            }).validate(SIGNATURE_LABEL, taggedSignature);
        new CBORAsymKeyValidator(p256.getPublic())
            .setTagPolicy(CBORCryptoUtils.POLICY.MANDATORY, new CBORCryptoUtils.Collector() {
                
                @Override
                public void foundData(CBORObject objectOrNull)
                        throws IOException, GeneralSecurityException {
                    assertTrue("id", 
                               objectOrNull.getTag()
                                   .getObject()
                                       .getArray()
                                           .getObject(0)
                                               .getString().equals(objectId));
                }
            }).validate(SIGNATURE_LABEL, taggedSignature);

        long tag = 18;
        // 1-dimensional tag
        tagSigner = new CBORAsymKeySigner(p256.getPrivate())
            .setIntercepter(new CBORCryptoUtils.Intercepter() {
                
                @Override
                public CBORObject wrap(CBORMap mapToSign) 
                        throws IOException, GeneralSecurityException {
                    return new CBORTag(tag, mapToSign);
                }
                
        });
        
        taggedSignature = tagSigner.sign(SIGNATURE_LABEL, createDataToBeSigned());
        new CBORAsymKeyValidator(p256.getPublic())
            .setTagPolicy(CBORCryptoUtils.POLICY.MANDATORY, new CBORCryptoUtils.Collector() {
                
                @Override
                public void foundData(CBORObject objectOrNull)
                        throws IOException, GeneralSecurityException {
                    assertTrue("tagn", tag == objectOrNull.getTag().getTagNumber());
                }
            }).validate(SIGNATURE_LABEL, taggedSignature);
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
                    CBORObject encrypted = encrypter.encrypt(dataToEncrypt);
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
                    CBORObject encrypted = encrypter.encrypt(dataToEncrypt);
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
        CBORObject p256Encrypted = p256Encrypter.encrypt(dataToEncrypt);
        assertTrue("enc/dec", 
                ArrayUtil.compare(new CBORAsymKeyDecrypter(
                        p256.getPrivate()).decrypt(p256Encrypted),
                        dataToEncrypt));
        p256Encrypter.setKeyId(keyId);
        CBORObject p256EncryptedKeyId = p256Encrypter.encrypt(dataToEncrypt);
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
                            KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                            ContentEncryptionAlgorithms contentEncryptionAlgorithm)
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
            checkException(e, CBORCryptoUtils.STDERR_KEY_ID_PUBLIC);
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
                            
                                    p256Encrypted.getMap()
                                        .setObject(new CBORInteger(-2), new CBORInteger(5)));
            fail("must not run");
        } catch (Exception e) {
            checkException(e, "Map key -2 with argument of type=INTEGER with value=5 was never read");
        }
        try {
            new CBORAsymKeyDecrypter(
                        p256.getPrivate()).decrypt(
                                     p256Encrypted.getMap()
                            .getObject(KEY_ENCRYPTION_LABEL)
                            .getMap().removeObject(ALGORITHM_LABEL));
            fail("must not run");
        } catch (Exception e) {
            checkException(e, "Missing key: 1");
        }

        CBORObject p256CertEncrypted = new CBORX509Encrypter(p256CertPath,
                                                             KeyEncryptionAlgorithms.ECDH_ES_A128KW,
                                                             ContentEncryptionAlgorithms.A256GCM)
                .encrypt(dataToEncrypt);
 
        assertTrue("enc/dec", 
                ArrayUtil.compare(new CBORX509Decrypter(new CBORX509Decrypter.KeyLocator() {

                    @Override
                    public PrivateKey locate(X509Certificate[] certificatePath,
                                             KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                             ContentEncryptionAlgorithms contentEncryptionAlgorithm)
                            throws IOException, GeneralSecurityException {
                        assertTrue("cert", 
                                CBORCryptoUtils.encodeCertificateArray(certificatePath)
                                  .equals(CBORCryptoUtils.encodeCertificateArray(p256CertPath)));
                        assertTrue("kea", keyEncryptionAlgorithm == 
                                          KeyEncryptionAlgorithms.ECDH_ES_A128KW);
                        assertTrue("cea", contentEncryptionAlgorithm == 
                                          ContentEncryptionAlgorithms.A256GCM);
                        return p256.getPrivate();
                    }
                }).decrypt(p256CertEncrypted), dataToEncrypt));
        
        try {
            new CBORX509Encrypter(p256CertPath,
                    KeyEncryptionAlgorithms.ECDH_ES_A128KW,
                    ContentEncryptionAlgorithms.A256GCM)
                .setKeyId("illigal").encrypt(dataToEncrypt);
            fail("must not run");
        } catch (Exception e) {
            checkException(e, CBORCryptoUtils.STDERR_KEY_ID_PUBLIC);
        }

        CBORObject a256Encrypted = new CBORSymKeyEncrypter(symmetricKeys.getValue(256),
                                            ContentEncryptionAlgorithms.A256GCM)
                                                .encrypt(dataToEncrypt);
        
        CBORSymKeyDecrypter a256Decrypter = new CBORSymKeyDecrypter(symmetricKeys.getValue(256));
        assertTrue("enc/dec", 
                ArrayUtil.compare(a256Decrypter.decrypt(a256Encrypted),
                        dataToEncrypt));
        
        try {
            a256Decrypter.decrypt(
                a256Encrypted.getMap().setObject(KEY_ENCRYPTION_LABEL, 
                        new CBORMap().setObject(ALGORITHM_LABEL,
                                new CBORInteger(600))));
            fail("must not run");
        } catch (Exception e) {
            checkException(e, "Map key 1 with argument of type=INTEGER with value=600 was never read");
        }
        
        String objectId = "https://example.com/myobject";
        CBOREncrypter taggedX25519Encrypter = new CBORAsymKeyEncrypter(x25519.getPublic(),
                                         KeyEncryptionAlgorithms.ECDH_ES_A256KW,
                                         ContentEncryptionAlgorithms.A256GCM)
            .setKeyId("mykey")
            .setIntercepter(new CBORCryptoUtils.Intercepter() {
                
                @Override
                public CBORObject wrap(CBORMap encryptionObject)
                        throws IOException, GeneralSecurityException {
                    return new CBORTag(objectId, encryptionObject);
                }
                
            });

        taggedX25519Encrypter = new CBORAsymKeyEncrypter(x25519.getPublic(),
                                         KeyEncryptionAlgorithms.ECDH_ES_A256KW,
                                         ContentEncryptionAlgorithms.A256GCM)
            .setKeyId("mykey")
            .setIntercepter(new CBORCryptoUtils.Intercepter() {
                
                @Override
                public CBORObject wrap(CBORMap encryptionObject)
                        throws IOException, GeneralSecurityException {
                    // 2-dimensional
                    return new CBORTag(objectId, encryptionObject);
                }
                
                @Override
                public CBORObject getCustomData() {
                    // Custom data as well
                    return new CBORArray().addObject(new CBORInteger(500));
                }
                
            });
        CBORObject taggedX25519Encrypted = taggedX25519Encrypter.encrypt(dataToEncrypt);
        try {
            assertTrue("enc/dec", 
                    ArrayUtil.compare(new CBORAsymKeyDecrypter(x25519.getPrivate())
                                          .decrypt(taggedX25519Encrypted),
                                      dataToEncrypt));
            fail("must fail");
        } catch (Exception e) {
            checkException(e, "Tag encountered. Policy: FORBIDDEN");
        }
        try {
            assertTrue("enc/dec", 
                    ArrayUtil.compare(new CBORAsymKeyDecrypter(x25519.getPrivate())
                    .setTagPolicy(CBORCryptoUtils.POLICY.MANDATORY, 
                                  new CBORCryptoUtils.Collector() {

                        @Override
                        public void foundData(CBORObject objectOrNull)
                                throws IOException, GeneralSecurityException {
                            objectOrNull.getTag();
                        }})
                    .decrypt(taggedX25519Encrypted), dataToEncrypt));
            fail("must fail");
        } catch (Exception e) {
            checkException(e, "Custom data encountered. Policy: FORBIDDEN");
        }
        assertTrue("enc/dec", 
                ArrayUtil.compare(new CBORAsymKeyDecrypter(x25519.getPrivate())
                    .setCustomDataPolicy(CBORCryptoUtils.POLICY.MANDATORY,
                                         new CBORCryptoUtils.Collector() {
                            
                            @Override
                            public void foundData(CBORObject objectOrNull)
                                    throws IOException, GeneralSecurityException {
                                assertTrue("data",
                                           objectOrNull.getArray().getObject(0).getInt() == 500);
                            }
                        })
                    .setTagPolicy(CBORCryptoUtils.POLICY.MANDATORY,
                                  new CBORCryptoUtils.Collector() {

                            @Override
                            public void foundData(CBORObject objectOrNull)
                                    throws IOException, GeneralSecurityException {
                                assertTrue("id", 
                                           objectOrNull.getTag()
                                               .getObject()
                                                   .getArray()
                                                       .getObject(0)
                                                           .getString().equals(objectId));
                            }
                              
                        })
                    .decrypt(taggedX25519Encrypted), dataToEncrypt));
  
        taggedX25519Encrypter = new CBORAsymKeyEncrypter(x25519.getPublic(),
                                         KeyEncryptionAlgorithms.ECDH_ES_A256KW,
                                         ContentEncryptionAlgorithms.A256GCM)
            .setKeyId("mykey")
            .setIntercepter(new CBORCryptoUtils.Intercepter() {
                
                    @Override
                    public CBORObject wrap(CBORMap encryptionObject)
                            throws IOException, GeneralSecurityException {
                        // 1-dimensional
                        return new CBORTag(9999999, encryptionObject);
                    }
                });

        taggedX25519Encrypted = taggedX25519Encrypter.encrypt(dataToEncrypt);
        assertTrue("enc/dec", 
                ArrayUtil.compare(new CBORAsymKeyDecrypter(x25519.getPrivate())
                    .setTagPolicy(CBORCryptoUtils.POLICY.MANDATORY,
                          new CBORCryptoUtils.Collector() {
                            
                            @Override
                            public void foundData(CBORObject objectOrNull)
                                    throws IOException, GeneralSecurityException {
                                assertTrue("tagn", objectOrNull.getTag().getTagNumber() == 9999999);
                            }
                        })
                    .decrypt(taggedX25519Encrypted), dataToEncrypt));
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
                             boolean sequenceFlag, 
                             boolean acceptNonDeterministic) throws IOException {
        String result = HexaDecimal.encode(
                CBORObject.decode(new ByteArrayInputStream(HexaDecimal.decode(hexInput)),
                                  sequenceFlag,
                                  acceptNonDeterministic,
                                  false,
                                  null).encode()).toUpperCase();
        assertTrue("Strange=" + result, hexExpectedResult.equals(result));
    }
    
    void constrainedMapKeyTest(String hexInput, 
                               boolean acceptNonDeterministic, 
                               boolean ok) throws IOException {
        try {
            CBORObject.decode(new ByteArrayInputStream(HexaDecimal.decode(hexInput)),
                              false,
                              acceptNonDeterministic,
                              true,
                              null);
            assertTrue("Should not execute", ok);
        } catch (Exception e) {
            assertFalse("Should not fail", ok);
            checkException(e, CBORMap.STDERR_CONSTRAINED_KEYS);
        }
    }

    @Test
    public void decodeWithOptions() throws Exception {
        parseStrangeCborHex("A204616B026166", "A202616604616B", false, true);
        parseStrangeCborHex("1817", "17", false, true);
        parseStrangeCborHex("1900D0", "18D0", false, true);
        parseStrangeCborHex("1A000080D0", "1980D0", false, true);
        parseStrangeCborHex("1B00000000800080D0", "1A800080D0", false, true);
        parseStrangeCborHex("C24D00431E0FAE6A7217CA9FFFFFFF", "C24C431E0FAE6A7217CA9FFFFFFF", 
                            false, true);
        parseStrangeCborHex("C242431E", "19431E", false, true);
        parseStrangeCborHex("C240", "00", false, true);

        // Note: read one object but don't care of the next which in this case is invalid as well
        parseStrangeCborHex("A202616604616BFF", "A202616604616B", true, false);
        
        constrainedMapKeyTest("A204646461746101656461746132", true, true);
        constrainedMapKeyTest("a204656461746132056464617461", false, true);
        constrainedMapKeyTest("A2613464646174616131656461746132", true, true);
        constrainedMapKeyTest("a2613165646174613261346464617461", false, true);
        constrainedMapKeyTest("a204656461746132056464617461", false, true);
        constrainedMapKeyTest("a205646461746165616c706861656461746132", true, false);
        constrainedMapKeyTest("a205646461746165616c706861656461746132", false, false);
        constrainedMapKeyTest("a2056464617461f94400656461746132", true, false);
        constrainedMapKeyTest("a2056464617461f94400656461746132", false, false);
        constrainedMapKeyTest("a2056464617461c24f07b426fab61f00de36399000000000656461746132", 
                              true, false);
        constrainedMapKeyTest("a2056464617461c24f07b426fab61f00de36399000000000656461746132",
                              false, false);
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
    
    private void conversionError(String badJson, boolean mustFail) throws Exception {
        try {
            CBORFromJSON.convert(badJson);
            assertFalse("Should fail on: " + badJson, mustFail);
        } catch (Exception e) {
            assertTrue("Should not fail on: " + badJson, mustFail);
        }
    }

    private void conversionError(String badJson) throws Exception {
        conversionError(badJson, true);
    }
    
    @Test
    public void cborSequences() throws Exception {
        byte[] sequence = HexaDecimal.decode("00A104F58105A1056464617461");
        InputStream inputStream = new ByteArrayInputStream(sequence);
        int position = 0;
        CBORObject cborObject;
        while ((cborObject = CBORObject.decode(inputStream, true, false, false, null)) != null) {
            byte[] rawCbor = cborObject.encode();
            assertTrue("Seq", ArrayUtil.compare(rawCbor, 0, sequence, position, rawCbor.length));
            position += rawCbor.length;
        }
        assertTrue("SeqEnd", sequence.length == position);

        assertTrue("SeqNull", 
                   CBORObject.decode(new ByteArrayInputStream(new byte[0]),
                                                true, 
                                                false,
                                                false,
                                                null) == null);
        sequence = new CBORSequenceBuilder()
            .addObject(new CBORString("Hello CBOR Sequence World!"))
            .addObject(new CBORArray()
                .addObject(new CBORFloatingPoint(4.5))
                .addObject(new CBORBoolean(true)))
            .encode();
        inputStream = new ByteArrayInputStream(sequence);
        position = 0;
        while ((cborObject = CBORObject.decode(inputStream, true, false, false, null)) != null) {
            byte[] rawCbor = cborObject.encode();
            assertTrue("Seq", ArrayUtil.compare(rawCbor, 0, sequence, position, rawCbor.length));
            position += rawCbor.length;
        }
        assertTrue("SeqEnd", sequence.length == position);
    }

    @Test
    public void json2CborConversions() throws Exception {
        String[] jsonTokens = new String[] {
                "{", "\"lab\"", ":", "true", "}"
        };
        CBORMap cborMap = new CBORMap()
            .setObject(new CBORString("lab"), new CBORBoolean(true));
        assertTrue("json", cborMap.equals(serializeJson(jsonTokens)));
        
        assertTrue("json", new CBORMap().equals(serializeJson(new String[] {"{","}"})));
        
        jsonTokens = new String[] {
                "{", "\"lab\"", ":", "true", "," ,"\"j\"",":", "2000", "}"
        };
        cborMap = new CBORMap()
            .setObject(new CBORString("lab"), new CBORBoolean(true))
            .setObject(new CBORString("j"), new CBORInteger(2000));
        assertTrue("json", cborMap.equals(serializeJson(jsonTokens)));
        
        assertTrue("json", new CBORArray().equals(serializeJson(new String[] {"[","]"})));
               
        assertTrue("json", new CBORString("hi").equals(serializeJson("\"hi\"")));
        assertTrue("json", new CBORString("").equals(serializeJson("\"\"")));
        assertTrue("json", new CBORString("\u20ac$\n\b\r\t\"\\ ").equals(serializeJson(
                                              "\"\\u20ac$\\u000a\\b\\r\\t\\\"\\\\ \"")));
        assertTrue("json", new CBORString("\u0123\u4567\u89ab\ucdef\uABCD\uEF00").equals(serializeJson(
                                              "\"\\u0123\\u4567\\u89ab\\ucdef\\uABCD\\uEF00\"")));
        assertTrue("json", new CBORBoolean(true).equals(serializeJson("true")));
        assertTrue("json", new CBORBoolean(false).equals(serializeJson("false")));
        assertTrue("json", new CBORNull().equals(serializeJson("null")));
        assertTrue("json", new CBORInteger(-234).equals(serializeJson("-234")));
        assertTrue("json", new CBORInteger(234).equals(serializeJson("234")));
        assertTrue("json", new CBORInteger(1).equals(serializeJson("1")));
        assertTrue("json", new CBORInteger(987654321).equals(serializeJson("0987654321")));
        assertTrue("json", new CBORBigInteger(new BigInteger("9007199254740992")).equals(serializeJson(
                                                             "9007199254740992")));
        
        CBORArray cborArray = new CBORArray()
            .addObject(new CBORString("hi"));
        assertTrue("json", cborArray.equals(serializeJson(new String[] {"[","\"hi\"","]"})));
        cborArray.addObject(new CBORMap())
                 .addObject(new CBORInteger(4));
        assertTrue("json", cborArray.equals(serializeJson(new String[] {
                "[","\"hi\"",",","{","}",",","4","]"})));
        cborArray.getObject(1).getMap().setObject(new CBORString("kurt"),
                                                  new CBORString("murt"));
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
        conversionError("-9007199254740993");
        conversionError("[6,]");
        conversionError("{6:8}");
        conversionError("{\"6\":8,}");
        conversionError("{\"6\",8}");
        conversionError("{} 6");
        conversionError("18446744073709551615");
        conversionError("9007199254740992", false);
        conversionError("-9007199254740992", false);
    }
    
    @Test
    public void keySerializing() throws Exception {
        for (KeyPair keyPair : new KeyPair[] {p256, x25519, ed25519, p521, r2048}) {
            CBORMap cborPrivateKey = CBORKeyPair.convert(keyPair);
            assertTrue("priv", 
                       CBORKeyPair.convert(cborPrivateKey)
                           .getPrivate().equals(keyPair.getPrivate()));
            assertTrue("pub", 
                       CBORKeyPair.convert(cborPrivateKey)
                           .getPublic().equals(keyPair.getPublic()));
            CBORMap cborPublicKey = CBORPublicKey.convert(keyPair.getPublic());
            assertTrue("pub", 
                       CBORPublicKey.convert(cborPublicKey).equals(keyPair.getPublic()));
            try {
                cborPrivateKey.setObject(new CBORString("key"), new CBORString("value"));
                CBORKeyPair.convert(cborPrivateKey);
                fail("must not execute");
            } catch (Exception e) {
                checkException(e, 
                    "Map key \"key\" with argument of type=TEXT_STRING with value=\"value\" was never read");
            }
            try {
                cborPublicKey.setObject(new CBORString("key"), new CBORString("value"));
                CBORPublicKey.convert(cborPublicKey);
                fail("must not execute");
            } catch (Exception e) {
                checkException(e, 
                    "Map key \"key\" with argument of type=TEXT_STRING with value=\"value\" was never read");
            }
        }
    }
    
    public static class ObjectOne extends CBORTypedObjectDecoder {

        int number;
        
        static final String OBJECT_ID   = "https://example.com/object-1";
        static final CBORObject INT_KEY = new CBORInteger(1);
        
        @Override
        protected void decode(CBORObject cborBody)
                throws IOException, GeneralSecurityException {
            number = cborBody.getMap().getObject(INT_KEY).getInt();
        }

        @Override
        public String getObjectId() {
            return OBJECT_ID;
        }
    }
    
    public static class ObjectTwo extends CBORTypedObjectDecoder {
        
        static final String OBJECT_ID = "https://example.com/object-2";
        
        String justAString;

        @Override
        protected void decode(CBORObject cborBody)
                throws IOException, GeneralSecurityException {
            justAString = cborBody.getString();
        }

        @Override
        public String getObjectId() {
            return OBJECT_ID;
        }
    }
    
    public static class ObjectThree extends CBORTypedObjectDecoder {
        
        String justAString;

        @Override
        protected void decode(CBORObject cborBody)
                throws IOException, GeneralSecurityException {
            justAString = cborBody.getString();
        }

        @Override
        public String getObjectId() {
            return "https://example.com/o3";
        }

    }

    static final CBORTypedObjectDecoderCache schemaCache = new CBORTypedObjectDecoderCache()
            .addToCache(ObjectOne.class)
            .addToCache(ObjectTwo.class);

    @Test
    public void schemas() throws IOException, GeneralSecurityException {
        CBORObject objectOne = new CBORTag(ObjectOne.OBJECT_ID,
                new CBORMap().setObject(ObjectOne.INT_KEY, new CBORInteger(-343)));
        CBORObject objectTwo = new CBORTag(ObjectTwo.OBJECT_ID, 
                new CBORString("Hi there!"));
        CBORObject o3 = new CBORTag("https://example.com/o3", 
                new CBORString("Hi there!"));
        try {
            schemaCache.addToCache(ObjectOne.class);
            fail("double");
        } catch (Exception e) {
            
        }
        
        CBORTypedObjectDecoder sco = schemaCache.decode(objectOne);
        assertTrue("inst", sco instanceof ObjectOne);
        assertTrue("data", ((ObjectOne)sco).number == -343);
        assertTrue("cbor", objectOne.equals(sco.getRoot()));
        sco = schemaCache.decode(objectTwo);
        assertTrue("inst", sco instanceof ObjectTwo);
        try {
            schemaCache.decode(o3);
            fail("should not");
        } catch (Exception e) {
            
        }
    }

    static final String DIAG_TEXT = "text\nj";
    static final String DIAG_BIG = "100000000000000000000000000";
    static final String DIAG_HEX = "1e";
    static final CBORObject DIAG_CBOR;
    static {
        try {
            DIAG_CBOR = new CBORMap()
                    .setObject(new CBORInteger(1), 
                            new CBORArray().addObject(new CBORString("Hi!")));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
    void diagFlag(String wrongs) {
        try {
            CBORDiagnosticNotationDecoder.decode(wrongs);
            fail("Should not");
        } catch (Exception e) {
            
        }
    }

    @Test
    public void diagnosticNotation() throws Exception {
        assertTrue("#",
                   CBORDiagnosticNotationDecoder.decode("# hi\r\n 1#commnt").getInt() == 1);
        assertTrue("/",
                   CBORDiagnosticNotationDecoder.decode("/ comment\n /1").getInt() == 1);
        String b64u = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        CBORObject decoded = CBORDiagnosticNotationDecoder.decode("b64'" + b64u + "'");
        assertTrue("b64u", b64u.equals(Base64URL.encode(decoded.getBytes())));
        String b64 = b64u.replace('-', '+').replace('_', '/');
        decoded = CBORDiagnosticNotationDecoder.decode("b64'" + b64 + "'");
        assertTrue("b64", b64u.equals(Base64URL.encode(decoded.getBytes())));
        assertTrue("dbl", CBORDiagnosticNotationDecoder.decode("3.5").getDouble() == 3.5);
        assertTrue("int", CBORDiagnosticNotationDecoder.decode("1000").getInt() == 1000);
        assertTrue("big", CBORDiagnosticNotationDecoder.decode(DIAG_BIG).getBigInteger().equals(
                new BigInteger(DIAG_BIG)));
        assertTrue("bigh", CBORDiagnosticNotationDecoder.decode(
                "0x" + DIAG_BIG).getBigInteger().equals(new BigInteger(DIAG_BIG, 16)));
        assertTrue("bigh-", CBORDiagnosticNotationDecoder.decode(
                "-0x" + DIAG_BIG).getBigInteger().equals(new BigInteger(DIAG_BIG, 16).negate()));
        assertTrue("hex", CBORDiagnosticNotationDecoder.decode(
                "-0x" + DIAG_HEX).getInt() == -30);
        assertTrue("bstr", 
                    ArrayUtil.compare(
                            CBORDiagnosticNotationDecoder.decode(
                                    "'" + DIAG_TEXT + "'").getBytes(),
                            DIAG_TEXT.getBytes("utf-8")));
        assertTrue("tstr", 
                   DIAG_TEXT.equals(CBORDiagnosticNotationDecoder.decode(
                           "\"" + DIAG_TEXT + "\"").getString()));
        assertTrue("tstr", 
                   DIAG_TEXT.equals(CBORDiagnosticNotationDecoder.decode(
                        "\"" + DIAG_TEXT.replace("te", "te\\\n") + "\"").getString()));
        assertTrue("emb", ArrayUtil.compare(
                          CBORDiagnosticNotationDecoder.decode(
                                  "<< " + DIAG_CBOR.toString() + ">>").getBytes(),
                          DIAG_CBOR.encode()));
        Double v = CBORDiagnosticNotationDecoder.decode("Infinity").getDouble();
        assertTrue("inf", v == Double.POSITIVE_INFINITY);
        v = CBORDiagnosticNotationDecoder.decode("-Infinity").getDouble();
        assertTrue("-inf", v == Double.NEGATIVE_INFINITY);
        v = CBORDiagnosticNotationDecoder.decode("NaN").getDouble();
        assertTrue("nan", v.isNaN());
        CBORObject[] seq = CBORDiagnosticNotationDecoder.decodeSequence("1,\"" + DIAG_TEXT + "\"");
        assertTrue("seq", seq.length == 2);
        assertTrue("seqi", seq[0].getInt() == 1);
        assertTrue("seqs", seq[1].getString().equals(DIAG_TEXT));
        
        diagFlag("0x ");
        diagFlag("056(8)");  // leading zero
        diagFlag("-56(8)");  // Neg
        CBORDiagnosticNotationDecoder.decode("18446744073709551615(8)");
        diagFlag("18446744073709551616(8)");  // Too large
        CBORDiagnosticNotationDecoder.decode("1.0e+300");
        diagFlag("1.0e+500");  // Too large
    }

    void utf8DecoderTest(String hex, boolean ok) {
        byte[] cbor = HexaDecimal.decode(hex);
        try {
            byte[] roundTrip = CBORObject.decode(cbor).encode();
            assertTrue("OK", ok);
            assertTrue("Conv", ArrayUtil.compare(cbor, roundTrip));
        } catch (Exception e) {
            assertFalse("No good", ok);
        }
    }

    void utf8EncoderTest(String string, boolean ok) {
         try {
            String encodedString = CBORDiagnosticNotationDecoder.decode(
                    "\"" + string + "\"").getString();
            assertTrue("OK", ok);
            assertTrue("Conv", string.equals(encodedString));
            byte[] encodedBytes = CBORDiagnosticNotationDecoder.decode(
                    "'" + string + "'").getBytes();
            assertTrue("OK", ok);
            assertTrue("Conv2", ArrayUtil.compare(encodedBytes, string.getBytes("utf-8")));
        } catch (Exception e) {
            assertFalse("No good", ok);
        }
    }

    @Test
    public void utf8Test() {
        utf8DecoderTest("62c328", false);
        utf8DecoderTest("64f0288cbc", false);
        utf8DecoderTest("64f0908cbc", true);
        utf8EncoderTest("\uD83D", false);
        utf8EncoderTest("\uD83D\uDE2D", true);
    }
 }
