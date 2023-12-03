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

import java.util.Arrays;
import java.util.Locale;

import org.junit.BeforeClass;
import org.junit.Test;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.CryptoException;
import org.webpki.crypto.HmacAlgorithms;
import org.webpki.crypto.HmacSignerInterface;
import org.webpki.crypto.HmacVerifierInterface;
import org.webpki.crypto.KeyEncryptionAlgorithms;
import org.webpki.crypto.SignatureWrapper;
import org.webpki.crypto.X509SignerInterface;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.EncryptionCore;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;
import org.webpki.json.SymmetricKeys;

import org.webpki.util.Base64URL;
import org.webpki.util.HexaDecimal;
import org.webpki.util.IO;
import org.webpki.util.PEMDecoder;
import org.webpki.util.UTF8;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * CBOR JUnit suite
 */
public class CBORTest {

    static final byte[] dataToEncrypt = UTF8.encode(
            "The quick brown fox jumps over the lazy bear");

    @BeforeClass
    public static void openFile() throws Exception {
        Locale.setDefault(Locale.FRANCE);  // Should create HUGE problems :-)
        baseKey = System.clearProperty("test.keys") + File.separator;
        CustomCryptoProvider.forcedLoad(false);
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
        p256CertPath = PEMDecoder.getCertificatePath(IO.readFile(baseKey + "p256certpath.pem"));
    }
    
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
        LONG   (false), 
        ULONG  (true),
        INT    (false), 
        UINT   (true),
        SHORT  (false), 
        USHORT (true),
        BYTE   (false), 
        UBYTE  (true);
        
        boolean unsigned;
        
        IntegerVariations(boolean unsigned) {
            this.unsigned = unsigned;
        }
    };
    
    static CBORInt SIGNATURE_LABEL = new CBORInt(-1);
    
    static KeyPair readJwk(String keyType) throws Exception {
        JSONObjectReader jwkPlus = JSONParser.parse(
                IO.readFile(baseKey + keyType + "privatekey.jwk"));
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
    
    void binaryCompare(CBORObject cborObject, String hex) {
        byte[] cbor = cborObject.encode();
        String actual = HexaDecimal.encode(cbor);
        hex = hex.toLowerCase();
        assertTrue("binary h=" + hex + " c=" + actual, hex.equals(actual));
        CBORObject cborO = CBORObject.decode(cbor);
        String decS = cborO.toString();
        String origS = cborObject.toString();
        assertTrue("bc d=" + decS + " o=" + origS, decS.equals(origS));
    }

    void textCompare(CBORObject cborObject, String text) {
        String actual = cborObject.toString();
        assertTrue("text=\n" + actual + "\n" + text, text.equals(actual));
    }

    CBORObject parseCborHex(String hex) {
        byte[] cbor = HexaDecimal.decode(hex);
        CBORObject cborObject = CBORObject.decode(cbor);
        assertTrue("phex: " + hex, Arrays.equals(cbor, cborObject.encode()));
        return cborObject;
    }

    void integerTest(long value, 
                     boolean forceUnsigned, 
                     boolean set, 
                     String hex) {
        CBORObject cborObject = set ? 
                new CBORInt(value, forceUnsigned) : new CBORInt(value);
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

    void integerTest(long value, String hex) {
        integerTest(value, false, false, hex);
    }
    
    long ucheck(long v, long mask) {
        if (v < 0) {
            fail("<");
        } else {
            assertTrue(">=0", (v & mask) == v);
        }
        return v;
    }
    
    void integerTest(String value, IntegerVariations variation, boolean mustFail) {
        BigInteger bigInteger = new BigInteger(value);
        CBORObject CBORBigInt = new CBORBigInt(bigInteger);
        byte[] cbor = CBORBigInt.encode();
        CBORObject res = CBORObject.decode(cbor);
        assertTrue("int", res.equals(CBORBigInt));
        long v = 0;
        try {
            switch (variation) {
                case BYTE:
                    v = res.getByte();
                    break;
                case UBYTE:
                    v = ucheck(res.getUnsignedByte(), 0xff);
                    break;
                case SHORT:
                    v = res.getShort();
                    break;
                case USHORT:
                    v = ucheck(res.getUnsignedShort(), 0xffff);
                    break;
                case INT:
                    v = res.getInt();
                    break;
                case UINT:
                    v = ucheck(res.getUnsignedInt(), 0xffffffffL);
                    break;
                case LONG:
                    v = res.getLong();
                    break;
                case ULONG:
                    v = res.getUnsignedLong();
                    break;
            }
            assertFalse("Should not run: " + value, mustFail);
            assertTrue("=" + value, v == bigInteger.longValue());
        } catch (Exception e) {
            if (res.getType() == CBORTypes.BIGNUM) {
                checkException(e, "Is type: BIGNUM");
            } else {
                if (bigInteger.compareTo(BigInteger.TWO) < 0 && variation.unsigned) {
                    checkException(e, CBORObject.STDERR_NOT_UNSIGNED);
                } else {
                    String dataType = variation.toString().toLowerCase();
                    if (variation.unsigned) {
                        dataType = dataType.substring(1);
                    }
                    checkException(e, CBORObject.STDERR_INT_RANGE + dataType);
                }
            }
            assertTrue("Shouldn't throw: " + value + e.getMessage(), mustFail);
        }
    }

    void bigIntegerTest(String value, String hex) {
        byte[] cbor = new CBORBigInt(new BigInteger(value)).encode();
        String calc = HexaDecimal.encode(cbor);
        assertTrue("big int=" + value + " c=" + calc + " h=" + hex,
                hex.equals(HexaDecimal.encode(cbor)));
        CBORObject decodedBig = CBORObject.decode(cbor);
        String decS = decodedBig.getBigInteger().toString();
        assertTrue("Big2 d=" + decS + " v=" + value, value.equals(decS));
    }

    void stringTest(String string, String hex) {
        byte[] cbor = new CBORString(string).encode();
        String calc = HexaDecimal.encode(cbor);
        assertTrue("string=" + string + " c=" + calc + " h=" + hex, hex.equals(calc));
        assertTrue("string 2", CBORObject.decode(cbor).toString().equals("\"" + string + "\""));
    }

    void arrayTest(CBORArray cborArray, String hex) {
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
            CBORFloat cborFloat = (CBORFloat)parseCborHex(hex);
            int l;
            if (mustFail == 0) {
                switch (cborFloat.size()) {
                    case 2:
                        l = 3;
                        break;
                    case 4:
                        l = 5;
                        break;
                    default:
                        l = 9;
                        break;
                }
                assertTrue("ieee", l == cborFloat.encode().length);
                assertTrue("diag"+ asText, asText.equals(cborFloat.toString()));
            }
            assertFalse("Double should fail", mustFail == 1);
            Double d = cborFloat.getDouble();
            assertTrue("Equal d=" + d + " v=" + v, (d.compareTo(v)) == 0 ^ (mustFail != 0));
        } catch (Exception e) {
            assertTrue("Ok fail", mustFail != 0);
            checkException(e, CBORObject.STDERR_NON_DETERMINISTIC_FLOAT);
        }
    }
    
    void floatTest(String asText, String hex, boolean mustFail) {
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
    public void assortedTests() {
        CBORArray cborArray = new CBORArray()
            .add(new CBORInt(1))
            .add(new CBORArray()
                .add(new CBORInt(2))
                .add(new CBORInt(3)))
            .add(new CBORArray()
                .add(new CBORInt(4))
                .add(new CBORInt(5)));
        textCompare(cborArray,
                "[1, [2, 3], [4, 5]]");
        binaryCompare(cborArray,"8301820203820405");

        cborArray = new CBORArray()
            .add(new CBORInt(1))
            .add(new CBORMap()
                .set(new CBORString("best"), new CBORInt(2))
                .set(new CBORString("best2"), new CBORInt(3))
                .set(new CBORString("another"), new CBORInt(4)))
            .add(new CBORArray()
                .add(new CBORInt(5))
                .add(new CBORInt(6)));
        textCompare(cborArray,
                "[1, {\n  \"best\": 2,\n  \"best2\": 3,\n  \"another\": 4\n}, [5, 6]]");
        binaryCompare(cborArray,
                      "8301a36462657374026562657374320367616e6f7468657204820506");

        cborArray = new CBORArray()
            .add(new CBORInt(1))
            .add(new CBORMap()
                .set(new CBORInt(8), new CBORInt(2))
                .set(new CBORInt(58), new CBORInt(3))
                .set(new CBORInt(-90), new CBORNull())
                .set(new CBORInt(-4), new CBORArray()
                    .add(new CBORBoolean(true))
                    .add(new CBORBoolean(false))))
            .add(new CBORArray()
                .add(new CBORInt(4))
                .add(new CBORInt(5)));
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
        
        integerTest("-9223372036854775808",  IntegerVariations.LONG, false);
        integerTest("-9223372036854775809",  IntegerVariations.LONG, true);
        integerTest("9223372036854775807",   IntegerVariations.LONG, false);
        integerTest("9223372036854775808",   IntegerVariations.LONG, true);
        integerTest("-18446744073709551616", IntegerVariations.LONG, true);
        integerTest("-18446744073709551617", IntegerVariations.LONG, true);
        integerTest("18446744073709551616",  IntegerVariations.LONG, true);

        integerTest("18446744073709551615",  IntegerVariations.ULONG, false);
        integerTest("0",                     IntegerVariations.ULONG, false);
        integerTest("18446744073709551615",  IntegerVariations.ULONG, false);
        integerTest("18446744073709551616",  IntegerVariations.ULONG, true);
        integerTest("-1",                    IntegerVariations.ULONG, true);

        integerTest("-2147483648", IntegerVariations.INT, false);
        integerTest("-2147483649", IntegerVariations.INT, true);
        integerTest("2147483647",  IntegerVariations.INT, false);
        integerTest("2147483648",  IntegerVariations.INT, true);

        integerTest("-2147483649", IntegerVariations.UINT, true);
        integerTest("4294967295",  IntegerVariations.UINT, false);
        integerTest("4294967296",  IntegerVariations.UINT, true);

        integerTest("-32768", IntegerVariations.SHORT, false);
        integerTest("-32769", IntegerVariations.SHORT, true);
        integerTest("32767",  IntegerVariations.SHORT, false);
        integerTest("32768",  IntegerVariations.SHORT, true);

        integerTest("-2",    IntegerVariations.USHORT, true);
        integerTest("65535", IntegerVariations.USHORT, false);
        integerTest("65536", IntegerVariations.USHORT, true);
        
        integerTest("-128",  IntegerVariations.BYTE, false);
        integerTest("-129",  IntegerVariations.BYTE, true);
        integerTest("127",   IntegerVariations.BYTE, false);
        integerTest("128",   IntegerVariations.BYTE, true);

        integerTest("-2",  IntegerVariations.UBYTE, true);
        integerTest("255", IntegerVariations.UBYTE, false);
        integerTest("256", IntegerVariations.UBYTE, true);
        
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
                .add(new CBORInt(1))
                .add(new CBORInt(2))
                .add(new CBORInt(3)), "83010203");
        
//        unsupportedTag("C07819323032312D30352D30315430363A33373A35352B30313A3030");
        unsupportedTag("1C");
        
        // These numbers are supposed to be tie-breakers...
        doubleTest("10.55999755859375",          "FA4128F5C0");
        doubleTest("-1.401298464324817e-45",     "FA80000001");
        doubleTest("1.4012986313726115e-45",     "FB36A0000020000000");
        doubleTest("-9.183549615799121e-41",     "FA80010000");
        doubleTest("-1.8367099231598242e-40",    "FA80020000");
        doubleTest("-3.6734198463196485e-40",    "FA80040000");
        doubleTest("-7.346839692639297e-40",     "FA80080000");
        doubleTest("-1.4693679385278594e-39",    "FA80100000");
        doubleTest("-2.938735877055719e-39",     "FA80200000");
        doubleTest("-5.877471754111438e-39",     "FA80400000");
        doubleTest("-1.1754943508222875e-38",    "FA80800000");
        doubleTest("-2.9387358770557184e-39",    "FBB7EFFFFFFFFFFFFF");
        doubleTest("-1.1754943508222875e-38",    "FA80800000");
        doubleTest("-3.1691265005705735e+29",    "FAF0800000");
        doubleTest("-2.076918743413931e+34",     "FAF8800000");
        doubleTest("-5.316911983139664e+36",     "FAFC800000");
        doubleTest("-2.1267647932558654e+37",    "FAFD800000");
        doubleTest("3.4028234663852886e+38",     "FA7F7FFFFF");
        doubleTest("3.402823466385289e+38",      "FB47EFFFFFE0000001");
        doubleTest("-8.507059173023462e+37",     "FAFE800000");
        doubleTest("-3.090948894593554e+30",     "FAF21C0D94");
        doubleTest("10.559999942779541",         "FB40251EB850000000");
        doubleTest("10.559998512268066",         "FA4128F5C1");
        doubleTest("1.0e+48",                    "FB49E5E531A0A1C873");
        doubleTest("18440.0",                    "FA46901000");
        doubleTest("18448.0",                    "F97481");
        doubleTest("0.000030517578125",          "F90200");
        doubleTest("0.00003057718276977539",     "F90201");
        doubleTest("0.00006097555160522461",     "F903FF");
        doubleTest("0.00006103515625",           "F90400");
        doubleTest("0.000030547380447387695",    "FA38002000");
        doubleTest("0.000030584633350372314",    "FA38004800");
        doubleTest("-5.960464477539062e-8",      "FBBE6FFFFFFFFFFFFF");
        doubleTest("5.960464477539063e-8",       "F90001");
        doubleTest("-5.960464477539064e-8",      "FBBE70000000000001");
        doubleTest("5.960465188081798e-8",       "FA33800001");
        doubleTest("-5.960464477539063e-8",      "F98001");
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
            set(key, new CBORInt(objectNumber++));
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
    
    void preSortTest(CBORMap cborMap1, CBORMap cborMap2, boolean fail) {
        cborMap1.set(new CBORInt(1), new CBORString("1"));
        cborMap1.set(new CBORInt(2), new CBORString("2"));
        try {
            cborMap2.set(new CBORInt(2), new CBORString("2"));
            cborMap2.set(new CBORInt(1), new CBORString("1"));
            assertFalse("Should", fail);
        } catch (Exception e) {
            assertTrue("Should not", fail);
        }
    }

    void sortMe(int[] values) {
        int min = 1000;
        int max = -1;
        for (int i : values) {
            if (i < min) min = i;
            if (i > max) max = i;
        }
        CBORMap cborMap = new CBORMap();
        for (int i = 0; i < values.length; i++) {
            cborMap.set(new CBORInt(values[i]), new CBORString("ju"));
            assertFalse("min", cborMap.containsKey(new CBORInt(min - 1)));
            assertFalse("max", cborMap.containsKey(new CBORInt(max + 1)));
            for (int j = 0; j <= i; j++) {
                assertTrue("yes", cborMap.containsKey(new CBORInt(values[j])));
                assertFalse("no", cborMap.containsKey(new CBORInt(values[j] + 1)));
            }
        }
        CBORObject.decode(cborMap.encode());
    }
    
    void sortingTest(String[] expectedOrder) throws Exception{
        MapTest m = new MapTest();
        m.insert(new CBORInt(10))
         .insert(new CBORArray().add(new CBORInt(100)))
         .insert(new CBORInt(-1))
         .insert(new CBORBoolean(false))
         .insert(new CBORArray().add(new CBORInt(-1)))
         .insert(new CBORInt(100))
         .insert(new CBORString("aaa"))
         .insert(new CBORString("z"))
         .insert(new CBORString("aa"));
        assertTrue("size", m.size() == expectedOrder.length);
        while (m.size() > 0) {
            CBORObject removed = m.getKeys()[m.size() - 1];
            int i = 0;
            for (CBORObject key : m.getKeys()) {
                m.get(key);
                String expected = expectedOrder[i++];
                assertTrue("key=" + key + " exp=" + expected, key.toString().equals(expected));
            }
            m.remove(removed);
        }
    }
    
    @Test
    public void mapperTest() throws Exception {
        sortingTest(RFC8949_SORTING);
        sortMe(new int[] {0, 2, 4, 6});
        sortMe(new int[] {0, 2, 6, 4});
        sortMe(new int[] {7,1,5,11,9,13,3});
        sortMe(new int[] {8, 2, 10});
        preSortTest(new CBORMap(), new CBORMap(), false);
        preSortTest(new CBORMap(false), new CBORMap(false), false);
        preSortTest(new CBORMap(true), new CBORMap(true), true);
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
                Arrays.equals(cbor,
                          CBORObject.decode(
                                  new StrangeReader(cbor), false, false, null).encode()));

        assertTrue("bt", 
                Arrays.equals(cbor,
                          CBORObject.decode(new StrangeReader(cbor), 
                                            false, false, cbor.length).encode()));
        try {
            CBORObject.decode(new ByteArrayInputStream(HexaDecimal.decode("7BFFFFFFFFFFFFFFFF00")), 
                              false, false, null);
            fail("Not valid");
        } catch (Exception e) {
            checkException(e, CBORObject.STDERR_N_RANGE_ERROR + "-1");
        }
        try {
            CBORObject.decode(new ByteArrayInputStream(HexaDecimal.decode("7AFFFFFFFF00")), 
                              false, false, null);
            fail("Not valid");
        } catch (Exception e) {
            checkException(e, CBORObject.STDERR_N_RANGE_ERROR + "4294967295");
        }
        try {
            CBORObject.decode(new ByteArrayInputStream(HexaDecimal.decode("797FFF00")), 
                              false, false, 100);
            fail("Not valid");
        } catch (Exception e) {
            checkException(e, CBORObject.STDERR_READING_LIMIT);
        }
        try {
            CBORObject.decode(new ByteArrayInputStream(HexaDecimal.decode("7A7FFFFFFF00")), 
                              false, false, null);
            fail("Not valid");
        } catch (Exception e) {
            checkException(e, CBORObject.STDERR_READING_LIMIT);
        }
    }
 
    @Test
    public void accessTest() throws Exception {
        CBORObject cbor = parseCborHex("8301a40802183a032382f5f43859f6820405");
        try {
            ((CBORArray) cbor).get(0).getMap();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "Is type: INTEGER, requested: MAP");
        }

        try {
            ((CBORArray) cbor).get(1).getMap()
                    .get(new CBORInt(-91)).getInt();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "Missing key: -91");
        }
 
        assertTrue("v1", ((CBORArray) cbor).get(1).getMap()
                .get(new CBORInt(58)).getInt() == 3);

        assertTrue("v1", ((CBORArray) cbor).get(1).getMap()
                .getConditionally(new CBORInt(58), null).getInt() == 3);

        assertTrue("v1", ((CBORArray) cbor).get(1).getMap()
                .getConditionally(new CBORString("no way"), new CBORInt(10)).getInt() == 10);

        assertTrue("tag5", parseCborHex("C5626869").getTag().getTagNumber() == 5);
    }

    @Test
    public void unreadElementTest() throws Exception {
        CBORObject unread = null;
        try {
            unread = parseCborHex("8301a40802183a032382f5f43859f6820405");
            ((CBORArray) unread).get(0).getInt();
            unread.checkForUnread();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Map key 8 with argument of type=INTEGER with value=2 was never read");
        }

        try {
            unread = parseCborHex("8301a40802183a032382f5f43859f6820405");
            unread = ((CBORArray) unread).get(1).getMap();
            ((CBORMap)unread).get(new CBORInt(8)).getInt();
            ((CBORMap)unread).get(new CBORInt(58)).getInt();
            ((CBORArray)((CBORMap)unread).get(new CBORInt(-4))).get(0).getBoolean();
            unread.checkForUnread();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Array element of type=BOOLEAN with value=false was never read");
        }
        
        try {
            unread = parseCborHex("C5626869");
            unread = ((CBORTag) unread).getTag().getTaggedObject();
            unread.checkForUnread();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Data of type=STRING with value=\"hi\" was never read");
        }
        unread.getString();
        unread.checkForUnread();
        
        /*
             .addObject(new CBORInt(1))
            .addObject(new CBORMap()
                .setObject(8, new CBORInt(2))
                .setObject(58, new CBORInt(3))
                .setObject(-90, new CBORNull())
                .setObject(-4, new CBORArray()
                    .addObject(new CBORBool(true))
                    .addObject(new CBORBool(false))))
 */

        // If you just want to mark an item as "read" you can use scan();
        try {
            unread = parseCborHex("8301a40802183a032382f5f43859f6820405");
            unread = ((CBORArray) unread).get(1).getMap();
            ((CBORMap)unread).get(new CBORInt(8)).getInt();
            ((CBORMap)unread).get(new CBORInt(58)).getInt();
            ((CBORArray)((CBORMap)unread).get(new CBORInt(-4))).get(0).scan();
            unread.checkForUnread();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Array element of type=BOOLEAN with value=false was never read");
        }

        // Getting an object without reading the value is considered as "unread".
        try {
            unread = parseCborHex("8301a40802183a032382f5f43859f6820405");
            unread = ((CBORArray) unread).get(1).getMap();
            ((CBORMap)unread).get(new CBORInt(8)).getInt();
            ((CBORMap)unread).get(new CBORInt(58)).getInt();
            ((CBORArray)((CBORMap)unread).get(new CBORInt(-4))).get(0);
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
                "Map key 7 with argument of type=STRING with value=\"mydata\" was never read");
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
                "Is type: INTEGER, requested: BYTES");
        }
        try {
            cborObject.getDouble();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Is type: INTEGER, requested: FLOATING_POINT");
        }
        try {
            new CBORMap().set(null, new CBORInt(1));
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, CBORObject.STDERR_ARGUMENT_IS_NULL);
        }
        try {
            new CBORMap().set(new CBORInt(1), null);
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, CBORObject.STDERR_ARGUMENT_IS_NULL);
        }
        try {
            new CBORMap().get(null);
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
            checkException(e, CBORObject.STDERR_NON_DETERMINISTIC_N);
        }

        try {
            parseCborHex("c24900ffffffffffffffff");
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, CBORObject.STDERR_NON_DETERMINISTIC_BIGNUM);
        }

        try {
            parseCborHex("c24101");
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, CBORObject.STDERR_NON_DETERMINISTIC_BIGNUM);
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
                                         "FB36A0000000000000",
                                         "fb380fffffc0000000",
                                         "FAFF800000",
                                         "FA00000000",
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
                    CBORObject.STDERR_NON_DETERMINISTIC_N);
            }
        }
    }
    
    CBORMap createDataToBeSigned() throws IOException {
        return new CBORMap()
        .set(new CBORInt(1), new CBORMap()
                .set(new CBORInt(1), new CBORString("Space Shop"))
                .set(new CBORInt(2), new CBORString("100.00"))
                .set(new CBORInt(3), new CBORString("EUR")))
            .set(new CBORInt(2), new CBORString("spaceshop.com"))
            .set(new CBORInt(3), new CBORString("FR7630002111110020050014382"))
            .set(new CBORInt(4), new CBORString("https://europeanpaymentsinitiative.eu/fwp"))
            .set(new CBORInt(5), new CBORString("62932"))
            .set(new CBORInt(6), new CBORString("2021-05-03T09:50:08Z"));
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
                            objectId == null ? cborMap : new CBORArray()
                                    .add(new CBORString(objectId))
                                    .add(cborMap));
                }
                
            });
            validator.setTagPolicy(CBORCryptoUtils.POLICY.MANDATORY, new CBORCryptoUtils.Collector() {
                
                @Override
                public void foundData(CBORObject objectOrNull) {
                    if (objectId == null) {
                        assertTrue("tagn", objectOrNull.getTag().getTagNumber() == tagNumber);
                    } else {
                        assertTrue("id", 
                                   objectOrNull.getTag()
                                       .getTaggedObject()
                                           .getArray()
                                               .get(0)
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
        CBORObject res = new CBORHmacSigner(symmetricKeys.getValue(size),
                           algorithm).sign(SIGNATURE_LABEL, tbs);
        byte[] sd = res.encode();
        CBORObject cborSd = CBORObject.decode(sd);
        new CBORHmacValidator(symmetricKeys.getValue(size)).validate(SIGNATURE_LABEL, cborSd);
        
        tbs = createDataToBeSigned();
         res = new CBORHmacSigner(new HmacSignerInterface() {

            @Override
            public byte[] signData(byte[] data) {
                return algorithm.digest(symmetricKeys.getValue(size), data);
            }

            @Override
            public HmacAlgorithms getAlgorithm() {
                return algorithm;
            }
            
        }).sign(SIGNATURE_LABEL, tbs);
        sd = res.encode();
        cborSd = CBORObject.decode(sd);
        new CBORHmacValidator(symmetricKeys.getValue(size)).validate(SIGNATURE_LABEL, cborSd);

        tbs = createDataToBeSigned();
        CBORObject keyId = new CBORString(symmetricKeys.getName(size));
        res = new CBORHmacSigner(symmetricKeys.getValue(size), algorithm).setKeyId(keyId)
            .sign(SIGNATURE_LABEL, tbs); 
        sd = res.encode();
        cborSd = CBORObject.decode(sd);
        new CBORHmacValidator(new HmacVerifierInterface() {

            @Override
            public boolean verifySignature(byte[] data, 
                                           byte[] digest, 
                                           HmacAlgorithms hmacAlgorithm, 
                                           String optionalKeyId) {
                if (!algorithm.equals(hmacAlgorithm)) {
                    throw new CryptoException("Algorithm error");
                }
                if (!keyId.getString().equals(optionalKeyId)) {
                    throw new CryptoException("Unknown keyId");
                }
                return Arrays.equals(algorithm.digest(symmetricKeys.getValue(size), data), digest);
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
                                        AsymSignatureAlgorithms signatureAlgorithm) {
                    return p256.getPublic();
                }
            }));

        signAndVerify(new CBORAsymKeySigner(p256.getPrivate()), 
            new CBORAsymKeyValidator(new CBORAsymKeyValidator.KeyLocator() {
                
                @Override
                public PublicKey locate(PublicKey optionalPublicKey, 
                                        CBORObject optionalKeyId,
                                        AsymSignatureAlgorithms signatureAlgorithm) {
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
                                        AsymSignatureAlgorithms signatureAlgorithm) {
                    return compareKeyId(keyIdP256, optionalKeyId) ? 
                                                 p256.getPublic() : p256_2.getPublic();
                }

            }));

        signAndVerify(new CBORX509Signer(p256.getPrivate(), p256CertPath),
            new CBORX509Validator(new CBORX509Validator.Parameters() {

                @Override
                public void verify(X509Certificate[] certificatePath,
                                  AsymSignatureAlgorithms signatureAlgorithm) {
                }

            }));

        signAndVerify(new CBORX509Signer(new X509SignerInterface() {

                @Override
                public byte[] signData(byte[] data) {
                    return SignatureWrapper.sign(p256.getPrivate(),
                                                 AsymSignatureAlgorithms.ECDSA_SHA256,
                                                 data,
                                                 null);
                    }
                
                @Override
                public AsymSignatureAlgorithms getAlgorithm() {
                    return AsymSignatureAlgorithms.ECDSA_SHA256;
                }
    
                @Override
                public X509Certificate[] getCertificatePath() {
                    return p256CertPath;
                }
                
            }), new CBORX509Validator(new CBORX509Validator.Parameters() {

                @Override
                public void verify(X509Certificate[] certificatePath,
                                  AsymSignatureAlgorithms signatureAlgorithm) {
                }

            }));
        
        try {
            signAndVerify(new CBORX509Signer(new X509SignerInterface() {
    
                    @Override
                    public byte[] signData(byte[] data) {
                        return SignatureWrapper.sign(p256.getPrivate(),
                                                     AsymSignatureAlgorithms.ECDSA_SHA256,
                                                     data,
                                                     null);
                    }
                    
                    @Override
                    public AsymSignatureAlgorithms getAlgorithm() {
                        return AsymSignatureAlgorithms.ECDSA_SHA384;
                    }
        
                    @Override
                    public X509Certificate[] getCertificatePath() {
                        return p256CertPath;
                    }
                    
                }), new CBORX509Validator(new CBORX509Validator.Parameters() {
    
                    @Override
                    public void verify(X509Certificate[] certificatePath,
                                      AsymSignatureAlgorithms signatureAlgorithm) {
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
                                      AsymSignatureAlgorithms signatureAlgorithm) {
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
                                      AsymSignatureAlgorithms signatureAlgorithm) {
                    }

                }));
            fail("Must not execute");
        } catch (Exception e) {
            // Deep errors are not checked for exact text
        }
        
        signAndVerify(new CBORAsymKeySigner(p256.getPrivate()).setPublicKey(p256.getPublic()), 
            new CBORAsymKeyValidator((optionalPublicKey,
                                      optionalKeyId,
                                      signatureAlgorithm) -> {
                // Lambda is cool?
                assertTrue("pk", p256.getPublic().equals(optionalPublicKey));
                return optionalPublicKey;
            }));

        try {
            signAndVerify(new CBORAsymKeySigner(p256.getPrivate()), 
                new CBORAsymKeyValidator(new CBORAsymKeyValidator.KeyLocator() {
                    
                    @Override
                    public PublicKey locate(PublicKey optionalPublicKey, 
                                            CBORObject optionalKeyId,
                                            AsymSignatureAlgorithms signatureAlgorithm) {
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
        
        // Testing the clone method
        CBORMap clone = createDataToBeSigned().getMap();
        CBORObject cloneSign = new CBORAsymKeySigner(p256.getPrivate())
            .setPublicKey(p256.getPublic())
            .setCloneMode(true)
            .sign(SIGNATURE_LABEL, clone);
        assertFalse("c1", clone.containsKey(SIGNATURE_LABEL));
        new CBORAsymKeyValidator(p256.getPublic()).validate(SIGNATURE_LABEL, cloneSign);
        cloneSign = new CBORAsymKeySigner(p256.getPrivate())
            .setPublicKey(p256.getPublic())
            .sign(SIGNATURE_LABEL, clone);
            assertTrue("c2", clone.containsKey(SIGNATURE_LABEL));
        new CBORAsymKeyValidator(p256.getPublic()).validate(SIGNATURE_LABEL, cloneSign);
        
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
                                            AsymSignatureAlgorithms signatureAlgorithm) {
                        if (compareKeyId(new CBORString("otherkey"), optionalKeyId)) {
                            return p256_2.getPublic();
                        }
                        throw new CryptoException("KeyId = " + optionalKeyId);
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
                public CBORObject wrap(CBORMap mapToSign) {
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
                public void foundData(CBORObject objectOrNull) {
                    assertTrue("id", 
                               objectOrNull.getTag()
                                   .getTaggedObject()
                                       .getArray()
                                           .get(0)
                                               .getString().equals(objectId));
                }
            }).validate(SIGNATURE_LABEL, taggedSignature);
        new CBORAsymKeyValidator(p256.getPublic())
            .setTagPolicy(CBORCryptoUtils.POLICY.MANDATORY, new CBORCryptoUtils.Collector() {
                
                @Override
                public void foundData(CBORObject objectOrNull) {
                    assertTrue("id", 
                               objectOrNull.getTag()
                                   .getTaggedObject()
                                       .getArray()
                                           .get(0)
                                               .getString().equals(objectId));
                }
            }).validate(SIGNATURE_LABEL, taggedSignature);

        long tag = 18;
        // 1-dimensional tag
        tagSigner = new CBORAsymKeySigner(p256.getPrivate())
            .setIntercepter(new CBORCryptoUtils.Intercepter() {
                
                @Override
                public CBORObject wrap(CBORMap mapToSign) {
                    return new CBORTag(tag, mapToSign);
                }
                
        });
        
        taggedSignature = tagSigner.sign(SIGNATURE_LABEL, createDataToBeSigned());
        new CBORAsymKeyValidator(p256.getPublic())
            .setTagPolicy(CBORCryptoUtils.POLICY.MANDATORY, new CBORCryptoUtils.Collector() {
                
                @Override
                public void foundData(CBORObject objectOrNull) {
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
                            Arrays.equals(new CBORAsymKeyDecrypter(
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
                            Arrays.equals(
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
                Arrays.equals(new CBORAsymKeyDecrypter(
                        p256.getPrivate()).decrypt(p256Encrypted),
                        dataToEncrypt));
        p256Encrypter.setKeyId(keyId);
        CBORObject p256EncryptedKeyId = p256Encrypter.encrypt(dataToEncrypt);
        assertTrue("enc/dec", 
                Arrays.equals(new CBORAsymKeyDecrypter(
                        p256.getPrivate()).decrypt(p256EncryptedKeyId),
                        dataToEncrypt));
        assertTrue("enc/dec", 
            Arrays.equals(new CBORAsymKeyDecrypter(
                new CBORAsymKeyDecrypter.DecrypterImpl() {
 
                    @Override
                    public PrivateKey locate(PublicKey optionalPublicKey, 
                                             CBORObject optionalKeyId,
                                             KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                             ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
                        return compareKeyId(keyId, optionalKeyId) ? p256.getPrivate() : null;
                    }
                    
                    @Override
                    public byte[] decrypt(PrivateKey privateKey,
                                          byte[] optionalEncryptedKey,
                                          PublicKey optionalEphemeralKey,
                                          KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                          ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
                        return EncryptionCore.receiverKeyAgreement(true, 
                                                                   privateKey, 
                                                                   keyEncryptionAlgorithm,
                                                                   contentEncryptionAlgorithm, 
                                                                   optionalEphemeralKey, 
                                                                   optionalEncryptedKey);
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
                                        .set(new CBORInt(-2), new CBORInt(5)));
            fail("must not run");
        } catch (Exception e) {
            checkException(e, "Map key -2 with argument of type=INTEGER with value=5 was never read");
        }
        try {
            CBORObject modified =  p256Encrypted;
            modified.getMap().get(KEY_ENCRYPTION_LABEL).getMap().remove(ALGORITHM_LABEL);
            new CBORAsymKeyDecrypter(
                        p256.getPrivate()).decrypt(modified);
            fail("must not run");
        } catch (Exception e) {
            checkException(e, "Missing key: 1");
        }

        CBORObject p256CertEncrypted = new CBORX509Encrypter(p256CertPath,
                                                             KeyEncryptionAlgorithms.ECDH_ES_A128KW,
                                                             ContentEncryptionAlgorithms.A256GCM)
                .encrypt(dataToEncrypt);
 
        assertTrue("enc/dec", 
                Arrays.equals(new CBORX509Decrypter(new CBORX509Decrypter.DecrypterImpl() {

                    @Override
                    public PrivateKey locate(X509Certificate[] certificatePath,
                                             KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                             ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
                        assertTrue("cert", 
                                CBORCryptoUtils.encodeCertificateArray(certificatePath)
                                  .equals(CBORCryptoUtils.encodeCertificateArray(p256CertPath)));
                        assertTrue("kea", keyEncryptionAlgorithm == 
                                          KeyEncryptionAlgorithms.ECDH_ES_A128KW);
                        assertTrue("cea", contentEncryptionAlgorithm == 
                                          ContentEncryptionAlgorithms.A256GCM);
                        return p256.getPrivate();                    }

                    @Override
                    public byte[] decrypt(PrivateKey privateKey,
                                          byte[] optionalEncryptedKey,
                                          PublicKey optionalEphemeralKey,
                                          KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                          ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
                        return EncryptionCore.receiverKeyAgreement(true, 
                                                                   privateKey, 
                                                                   keyEncryptionAlgorithm,
                                                                   contentEncryptionAlgorithm, 
                                                                   optionalEphemeralKey, 
                                                                   optionalEncryptedKey);
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
                Arrays.equals(a256Decrypter.decrypt(a256Encrypted),
                        dataToEncrypt));
        
        try {
            a256Decrypter.decrypt(
                a256Encrypted.getMap().set(KEY_ENCRYPTION_LABEL, 
                        new CBORMap().set(ALGORITHM_LABEL,
                                new CBORInt(600))));
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
                public CBORObject wrap(CBORMap encryptionObject) {
                    return new CBORTag(objectId, encryptionObject);
                }
                
            });

        taggedX25519Encrypter = new CBORAsymKeyEncrypter(x25519.getPublic(),
                                         KeyEncryptionAlgorithms.ECDH_ES_A256KW,
                                         ContentEncryptionAlgorithms.A256GCM)
            .setKeyId("mykey")
            .setIntercepter(new CBORCryptoUtils.Intercepter() {
                
                @Override
                public CBORObject wrap(CBORMap encryptionObject) {
                    // 2-dimensional
                    return new CBORTag(objectId, encryptionObject);
                }
                
                @Override
                public CBORObject getCustomData() {
                    // Custom data as well
                    return new CBORArray().add(new CBORInt(500));
                }
                
            });
        CBORObject taggedX25519Encrypted = taggedX25519Encrypter.encrypt(dataToEncrypt);
        try {
            assertTrue("enc/dec", 
                    Arrays.equals(new CBORAsymKeyDecrypter(x25519.getPrivate())
                                          .decrypt(taggedX25519Encrypted),
                                      dataToEncrypt));
            fail("must fail");
        } catch (Exception e) {
            checkException(e, "Tag encountered. Policy: FORBIDDEN");
        }
        try {
            assertTrue("enc/dec", 
                    Arrays.equals(new CBORAsymKeyDecrypter(x25519.getPrivate())
                    .setTagPolicy(CBORCryptoUtils.POLICY.MANDATORY, 
                                  new CBORCryptoUtils.Collector() {

                        @Override
                        public void foundData(CBORObject objectOrNull) {
                            objectOrNull.getTag();
                        }})
                    .decrypt(taggedX25519Encrypted), dataToEncrypt));
            fail("must fail");
        } catch (Exception e) {
            checkException(e, "Custom data encountered. Policy: FORBIDDEN");
        }
        assertTrue("enc/dec", 
                Arrays.equals(new CBORAsymKeyDecrypter(x25519.getPrivate())
                    .setCustomDataPolicy(CBORCryptoUtils.POLICY.MANDATORY,
                                         new CBORCryptoUtils.Collector() {
                            
                            @Override
                            public void foundData(CBORObject objectOrNull) {
                                assertTrue("data",
                                           objectOrNull.getArray().get(0).getInt() == 500);
                            }
                        })
                    .setTagPolicy(CBORCryptoUtils.POLICY.MANDATORY,
                                  new CBORCryptoUtils.Collector() {

                            @Override
                            public void foundData(CBORObject objectOrNull) {
                                assertTrue("id", 
                                           objectOrNull.getTag()
                                               .getTaggedObject()
                                                   .getArray()
                                                       .get(0)
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
                    public CBORObject wrap(CBORMap encryptionObject) {
                        // 1-dimensional
                        return new CBORTag(9999999, encryptionObject);
                    }
                });

        taggedX25519Encrypted = taggedX25519Encrypter.encrypt(dataToEncrypt);
        assertTrue("enc/dec", 
                Arrays.equals(new CBORAsymKeyDecrypter(x25519.getPrivate())
                    .setTagPolicy(CBORCryptoUtils.POLICY.MANDATORY,
                          new CBORCryptoUtils.Collector() {
                            
                            @Override
                            public void foundData(CBORObject objectOrNull) {
                                assertTrue("tagn", objectOrNull.getTag().getTagNumber() == 9999999);
                            }
                        })
                    .decrypt(taggedX25519Encrypted), dataToEncrypt));
    }
    
    void parseStrangeCborHex(String hexInput,
                             String hexExpectedResult,
                             boolean sequenceFlag, 
                             boolean acceptNonDeterministic) throws IOException {
        String result = HexaDecimal.encode(
                CBORObject.decode(new ByteArrayInputStream(HexaDecimal.decode(hexInput)),
                                  sequenceFlag,
                                  acceptNonDeterministic,
                                  null).encode()).toUpperCase();
        assertTrue("Strange=" + result, hexExpectedResult.equals(result));
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
        while ((cborObject = CBORObject.decode(inputStream, true, false, null)) != null) {
            byte[] rawCbor = cborObject.encode();
            assertTrue("Seq", Arrays.equals(rawCbor, 0, rawCbor.length, 
                                            sequence, position, position + rawCbor.length));
            position += rawCbor.length;
        }
        assertTrue("SeqEnd", sequence.length == position);

        assertTrue("SeqNull", 
                   CBORObject.decode(new ByteArrayInputStream(new byte[0]),
                                                true, 
                                                false,
                                                null) == null);
        CBORSequenceBuilder sequenceBuilder = new CBORSequenceBuilder()
            .add(new CBORString("Hello CBOR Sequence World!"))
            .add(new CBORArray()
                .add(new CBORFloat(4.5))
                .add(new CBORBoolean(true)));
        assertTrue("seqs",
                   sequenceBuilder.toString().equals("\"Hello CBOR Sequence World!\",\n" +
                                                     "[4.5, true]"));
        sequence = sequenceBuilder.encode();
        inputStream = new ByteArrayInputStream(sequence);
        position = 0;
        while ((cborObject = CBORObject.decode(inputStream, true, false, null)) != null) {
            byte[] rawCbor = cborObject.encode();
            assertTrue("Seq", Arrays.equals(rawCbor, 0, rawCbor.length,
                                            sequence, position, position + rawCbor.length));
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
            .set(new CBORString("lab"), new CBORBoolean(true));
        assertTrue("json", cborMap.equals(serializeJson(jsonTokens)));
        
        assertTrue("json", new CBORMap().equals(serializeJson(new String[] {"{","}"})));
        
        jsonTokens = new String[] {
                "{", "\"lab\"", ":", "true", "," ,"\"j\"",":", "2000", "}"
        };
        cborMap = new CBORMap()
            .set(new CBORString("lab"), new CBORBoolean(true))
            .set(new CBORString("j"), new CBORInt(2000));
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
        assertTrue("json", new CBORInt(-234).equals(serializeJson("-234")));
        assertTrue("json", new CBORInt(234).equals(serializeJson("234")));
        assertTrue("json", new CBORInt(1).equals(serializeJson("1")));
        assertTrue("json", new CBORInt(987654321).equals(serializeJson("0987654321")));
        assertTrue("json", new CBORBigInt(new BigInteger("9007199254740992")).equals(serializeJson(
                                                             "9007199254740992")));
        
        CBORArray cborArray = new CBORArray()
            .add(new CBORString("hi"));
        assertTrue("json", cborArray.equals(serializeJson(new String[] {"[","\"hi\"","]"})));
        cborArray.add(new CBORMap())
                 .add(new CBORInt(4));
        assertTrue("json", cborArray.equals(serializeJson(new String[] {
                "[","\"hi\"",",","{","}",",","4","]"})));
        cborArray.get(1).getMap().set(new CBORString("kurt"),
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
                cborPrivateKey.set(new CBORString("key"), new CBORString("value"));
                CBORKeyPair.convert(cborPrivateKey);
                fail("must not execute");
            } catch (Exception e) {
                checkException(e, 
                    "Map key \"key\" with argument of type=STRING with value=\"value\" was never read");
            }
            try {
                cborPublicKey.set(new CBORString("key"), new CBORString("value"));
                CBORPublicKey.convert(cborPublicKey);
                fail("must not execute");
            } catch (Exception e) {
                checkException(e, 
                    "Map key \"key\" with argument of type=STRING with value=\"value\" was never read");
            }
        }
    }
    
    public static class ObjectOne extends CBORTypedObjectDecoder {

        int number;
        
        static final String OBJECT_ID   = "https://example.com/object-1";
        static final CBORObject INT_KEY = new CBORInt(1);
        
        @Override
        protected void decode(CBORObject cborBody) {
            number = cborBody.getMap().get(INT_KEY).getInt();
        }

        @Override
        public String getObjectId() {
            return OBJECT_ID;
        }
    }
    
    public static class UncheckedObject extends CBORTypedObjectDecoder {

        int number;
        
        static final String OBJECT_ID   = "https://example.com/object-unc";
        static final CBORObject INT_KEY = new CBORInt(1);
        
        @Override
        protected void decode(CBORObject cborBody) {
            number = cborBody.getMap().get(INT_KEY).getInt();
        }

        @Override
        public String getObjectId() {
            return OBJECT_ID;
        }
        
        @Override
        protected boolean enableCheckForUnread() {
            return false;
        }
    }

    public static class ObjectTwo extends CBORTypedObjectDecoder {
        
        static final String OBJECT_ID = "https://example.com/object-2";
        
        String justAString;

        @Override
        protected void decode(CBORObject cborBody) {
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
        protected void decode(CBORObject cborBody) {
            justAString = cborBody.getString();
        }

        @Override
        public String getObjectId() {
            return "https://example.com/o3";
        }

    }

    static final CBORTypedObjectDecoderCache schemaCache = new CBORTypedObjectDecoderCache()
            .addToCache(ObjectOne.class)
            .addToCache(UncheckedObject.class)
            .addToCache(ObjectTwo.class);

    @Test
    public void schemas() throws IOException, GeneralSecurityException {
        CBORObject objectOne = new CBORTag(ObjectOne.OBJECT_ID,
                new CBORMap().set(ObjectOne.INT_KEY, new CBORInt(-343)));
        CBORObject objectTwo = new CBORTag(ObjectTwo.OBJECT_ID, 
                new CBORString("Hi there!"));
        CBORObject o3 = new CBORTag("https://example.com/o3", 
                new CBORString("Hi there!"));
        try {
            schemaCache.addToCache(ObjectOne.class);
            fail("double");
        } catch (Exception e) {
            
        }
        CBORObject noGoodObjectOne = new CBORTag(ObjectOne.OBJECT_ID,
                new CBORMap().set(ObjectOne.INT_KEY, new CBORInt(-343))
                             .set(new CBORString("key"), new CBORString("value")));
        
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
        
        try {
            sco = schemaCache.decode(noGoodObjectOne);
            fail("No good");
        } catch (Exception e) {
            checkException(e, "Map key ");
        }
        
        CBORObject uncheckedObject = new CBORTag(UncheckedObject.OBJECT_ID,
                new CBORMap().set(ObjectOne.INT_KEY, new CBORInt(-343))
                             .set(new CBORString("key"), new CBORString("value")));
        sco = schemaCache.decode(uncheckedObject);
    }

    static final String DIAG_TEXT = "text\nj";
    static final String DIAG_BIG = "100000000000000000000000000";
    static final String DIAG_HEX = "1e";
    static final CBORObject DIAG_CBOR;
    static {
        try {
            DIAG_CBOR = new CBORMap()
                    .set(new CBORInt(1), 
                            new CBORArray().add(new CBORString("Hi!")));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
    void diagFlag(String wrongs) {
        try {
            CBORDiagnosticNotation.decode(wrongs);
            fail("Should not");
        } catch (Exception e) {
            
        }
    }

    @Test
    public void diagnosticNotation() throws Exception {
        assertTrue("#",
                   CBORDiagnosticNotation.decode("# hi\r\n 1#commnt").getInt() == 1);
        assertTrue("/",
                   CBORDiagnosticNotation.decode("/ comment\n /1").getInt() == 1);
        String b64u = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        CBORObject decoded = CBORDiagnosticNotation.decode("b64'" + b64u + "'");
        assertTrue("b64u", b64u.equals(Base64URL.encode(decoded.getBytes())));
        String b64 = b64u.replace('-', '+').replace('_', '/');
        decoded = CBORDiagnosticNotation.decode("b64'" + b64 + "'");
        assertTrue("b64", b64u.equals(Base64URL.encode(decoded.getBytes())));
        assertTrue("dbl", CBORDiagnosticNotation.decode("3.5").getDouble() == 3.5);
        assertTrue("int", CBORDiagnosticNotation.decode("1000").getInt() == 1000);
        assertTrue("big", CBORDiagnosticNotation.decode(DIAG_BIG).getBigInteger().equals(
                new BigInteger(DIAG_BIG)));
        assertTrue("bigb", CBORDiagnosticNotation.decode(
                "0b" + DIAG_BIG).getBigInteger().equals(new BigInteger(DIAG_BIG, 2)));
        assertTrue("bigo", CBORDiagnosticNotation.decode(
                "0o" + DIAG_BIG).getBigInteger().equals(new BigInteger(DIAG_BIG, 8)));
        assertTrue("bigh", CBORDiagnosticNotation.decode(
                "0x" + DIAG_BIG).getBigInteger().equals(new BigInteger(DIAG_BIG, 16)));
        assertTrue("bigh-", CBORDiagnosticNotation.decode(
                "-0x" + DIAG_BIG).getBigInteger().equals(new BigInteger(DIAG_BIG, 16).negate()));
        assertTrue("hex", CBORDiagnosticNotation.decode(
                "-0x" + DIAG_HEX).getInt() == -30);
        assertTrue("bstr", 
                    Arrays.equals(
                            CBORDiagnosticNotation.decode(
                                    "'" + DIAG_TEXT + "'").getBytes(),
                            DIAG_TEXT.getBytes("utf-8")));
        assertTrue("tstr", 
                   DIAG_TEXT.equals(CBORDiagnosticNotation.decode(
                           "\"" + DIAG_TEXT + "\"").getString()));
        assertTrue("tstr", 
                   DIAG_TEXT.equals(CBORDiagnosticNotation.decode(
                        "\"" + DIAG_TEXT.replace("te", "te\\\n") + "\"").getString()));
        assertTrue("emb", Arrays.equals(
                          CBORDiagnosticNotation.decode(
                                  "<< " + DIAG_CBOR.toString() + ">>").getBytes(),
                          DIAG_CBOR.encode()));
        Double v = CBORDiagnosticNotation.decode("Infinity").getDouble();
        assertTrue("inf", v == Double.POSITIVE_INFINITY);
        v = CBORDiagnosticNotation.decode("-Infinity").getDouble();
        assertTrue("-inf", v == Double.NEGATIVE_INFINITY);
        v = CBORDiagnosticNotation.decode("NaN").getDouble();
        assertTrue("nan", v.isNaN());
        assertTrue("0.0", CBORDiagnosticNotation.decode("0.0").toString().equals("0.0"));
        assertTrue("-0.0", CBORDiagnosticNotation.decode("-0.0").toString().equals("-0.0"));
        CBORObject[] seq = CBORDiagnosticNotation.decodeSequence("1,\"" + DIAG_TEXT + "\"");
        assertTrue("seq", seq.length == 2);
        assertTrue("seqi", seq[0].getInt() == 1);
        assertTrue("seqs", seq[1].getString().equals(DIAG_TEXT));
        
        diagFlag("0x ");
        diagFlag("056(8)");  // leading zero
        diagFlag("-56(8)");  // Neg
        CBORDiagnosticNotation.decode("18446744073709551615(8)");
        diagFlag("18446744073709551616(8)");  // Too large
        CBORDiagnosticNotation.decode("1.0e+300");
        diagFlag("1.0e+500");  // Too large
        diagFlag("b64'00'");  // Bad B64
        diagFlag("h'0'");  // Bad Hex
        diagFlag("6_0");  // _ not permitted here
        assertTrue("_", CBORDiagnosticNotation.decode("0b100_000000001").getInt() == 2049);
        diagFlag("'unterminated");  // Bad string
        diagFlag("\"unterminated");  // Bad string
        
        String pretty = 
                "{\n" +
                "  1: \"text\\nnext\",\n" +
                "  2: [5.960465188081798e-8, h'abcdef', " + 
                "true, 0(\"2023-06-02T07:53:19Z\")]\n" +
                "}";
        
        CBORObject diag = CBORDiagnosticNotation.decode(pretty);
        assertTrue("diag1", pretty.equals(diag.toString()));
        assertTrue("diag2", pretty.replace(" ", "")
                                  .replace("\n", "").equals(diag.toDiagnosticNotation(false)));
        assertTrue("diag3", pretty.equals(diag.toDiagnosticNotation(true)));
    }

    void utf8DecoderTest(String hex, boolean ok) {
        byte[] cbor = HexaDecimal.decode(hex);
        try {
            byte[] roundTrip = CBORObject.decode(cbor).encode();
            assertTrue("OK", ok);
            assertTrue("Conv", Arrays.equals(cbor, roundTrip));
        } catch (Exception e) {
            assertFalse("No good", ok);
        }
    }

    void utf8EncoderTest(String string, boolean ok) {
         try {
            String encodedString = CBORDiagnosticNotation.decode(
                    "\"" + string + "\"").getString();
            assertTrue("OK", ok);
            assertTrue("Conv", string.equals(encodedString));
            byte[] encodedBytes = CBORDiagnosticNotation.decode(
                    "'" + string + "'").getBytes();
            assertTrue("OK", ok);
            assertTrue("Conv2", Arrays.equals(encodedBytes, string.getBytes("utf-8")));
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
    
    void compareHash(String hex) {
        String reverse = "";
        for (int q = Math.min(hex.length(), 8) - 1; q > 0; q -= 2) {
            reverse += hex.charAt(q - 1) + "" + hex.charAt(q);
        }
        assertTrue("hash" + reverse, parseCborHex(hex).hashCode() == Integer.parseInt(reverse, 16));
    }
    
    @Test
    public void hashTest() {
        compareHash("626869");
        compareHash("63686944");
        compareHash("6468694466");
        compareHash("60");
    }
 }
