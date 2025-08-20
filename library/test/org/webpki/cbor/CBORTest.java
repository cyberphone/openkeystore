/*
 *  Copyright 2006-2024 WebPKI.org (https://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://apache.org/licenses/LICENSE-2.0
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
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.cert.X509Certificate;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.X509EncodedKeySpec;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Locale;

import org.bouncycastle.util.encoders.Hex;
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
import static org.webpki.cbor.CBORInternal.*;

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
        INT64  (false), 
        UINT64 (true),
        INT32  (false), 
        UINT32 (true),
        INT16  (false), 
        UINT16 (true),
        INT8   (false), 
        UINT8  (true);
        
        boolean unsigned;
        
        IntegerVariations(boolean unsigned) {
            this.unsigned = unsigned;
        }
    };
    
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
        CBORObject cborO = CBORDecoder.decode(cbor);
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
        CBORObject cborObject = CBORDecoder.decode(cbor);
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
        CBORObject decodedInteger = CBORDecoder.decode(cbor);
        if (value != -1 || forceUnsigned) {
            long dv = forceUnsigned ? 
                    decodedInteger.getUint64()
                                    :
                    decodedInteger.getInt64();
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
        CBORObject res = CBORDecoder.decode(cbor);
        assertTrue("int", res.equals(CBORBigInt));
        long v = 0;
        try {
            switch (variation) {
                case INT8:
                    v = res.getInt8();
                    break;
                case UINT8:
                    v = ucheck(res.getUint8(), 0xff);
                    break;
                case INT16:
                    v = res.getInt16();
                    break;
                case UINT16:
                    v = ucheck(res.getUint16(), 0xffff);
                    break;
                case INT32:
                    v = res.getInt32();
                    break;
                case UINT32:
                    v = ucheck(res.getUint32(), 0xffffffffL);
                    break;
                case INT64:
                    v = res.getInt64();
                    break;
                case UINT64:
                    v = res.getUint64();
                    break;
            }
            assertFalse("Should not run: " + value, mustFail);
            assertTrue("=" + value, v == bigInteger.longValue());
        } catch (Exception e) {
            if (res instanceof CBORBigInt) {
                checkException(e, "Is type: CBORBigInt");
            } else {
                String dataType = variation.toString().toLowerCase();
                dataType = dataType.substring(0,1).toUpperCase() +
                    dataType.substring(1);
                checkException(e, CBORObject.STDERR_INT_RANGE + dataType);
            }
            assertTrue("Shouldn't throw: " + value + e.getMessage(), mustFail);
        }
    }

    void bigIntegerTest(String value, String hex) {
        byte[] cbor = new CBORBigInt(new BigInteger(value)).encode();
        String calc = HexaDecimal.encode(cbor);
        assertTrue("big int=" + value + " c=" + calc + " h=" + hex,
                hex.equals(HexaDecimal.encode(cbor)));
        CBORObject decodedBig = CBORDecoder.decode(cbor);
        String decS = decodedBig.getBigInteger().toString();
        assertTrue("Big2 d=" + decS + " v=" + value, value.equals(decS));
    }

    void intBigintTest(String value, String hex, boolean big) {
        BigInteger bigVal = new BigInteger(value);
        byte[] cbor = new CBORBigInt(bigVal).encode();
        String calc = HexaDecimal.encode(cbor);
        assertTrue("big1 int=" + value + " c=" + calc + " h=" + hex,
                hex.equals(HexaDecimal.encode(cbor)));
        CBORObject ib = CBORDecoder.decode(cbor);
        assertTrue("ib1", big ^ ib instanceof CBORInt);
        calc = HexaDecimal.encode(ib.encode());
        assertTrue("big2 int=" + value + " c=" + calc + " h=" + hex,
                hex.equals(HexaDecimal.encode(cbor)));
        assertTrue("dn=" + ib.toString(), value.equals(ib.toString()));
        assertTrue("dn2", value.equals(new CBORBigInt(bigVal).toString()));
        assertTrue("dn3", value.equals(ib.getBigInteger().toString()));
        try {
            new CBORInt(bigVal.longValue(), !value.startsWith("-"));
            assertFalse("should not", big);
        } catch (Exception e) {
            assertTrue("should", big);
            checkException(e, CBORInt.STDERR_INT_VALUE_OUT_OF_RANGE);
        }
        assertTrue("eq", ib.getBigInteger().compareTo(bigVal) == 0);
    }

    void stringTest(String string, String hex) {
        byte[] cbor = new CBORString(string).encode();
        String calc = HexaDecimal.encode(cbor);
        assertTrue("string=" + string + " c=" + calc + " h=" + hex, hex.equals(calc));
        assertTrue("string 2", CBORDecoder.decode(cbor).toString().equals("\"" + string + "\""));
    }

    void arrayTest(CBORArray cborArray, String hex) {
        byte[] cbor = cborArray.encode();
        String calc = HexaDecimal.encode(cbor);
        assertTrue(" c=" + calc + " h=" + hex, hex.equals(calc));
        assertTrue("arr", CBORDecoder.decode(cbor).toString().equals(cborArray.toString()));
    }

    void unsupportedTag(String hex) {
        try {
            parseCborHex(hex);
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                           CBORDecoder.STDERR_UNSUPPORTED_TAG + hex.substring(0, 2).toLowerCase());
        }
    }
    
    void doubleTest(String asText, String hex) {
        doubleTest(asText, hex, 0);
    }
    void doubleTest(String asText, String hex, int mustFail) {
        double v = Double.valueOf(asText);
        Double d = 0.0;
        try {
            CBORObject cborFloat = parseCborHex(hex);
            int l;
            if (mustFail == 0) {
                switch (cborFloat instanceof CBORNonFinite ? 
                       ((CBORNonFinite)cborFloat).length() : ((CBORFloat)cborFloat).length()) {
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
            d = cborFloat.getExtendedFloat64();
            assertTrue("Equal d=" + d + " v=" + v, (d.compareTo(v)) == 0 ^ (mustFail != 0));
        } catch (Exception e) {
            assertTrue("Ok fail", mustFail != 0);
            checkException(e, CBORDecoder.STDERR_NON_DETERMINISTIC_FLOAT);
        }
    }
    
    void float32Test(String asText, String hex, boolean mustFail) {
        double v = Double.valueOf(asText);
        CBORObject cborObject = parseCborHex(hex);
        try {
            if (cborObject instanceof CBORNonFinite) return;
            float f = cborObject.getFloat32();
            assertFalse("Should fail", mustFail);
            assertTrue("Comp", v == f);
        } catch (Exception e) {
            assertTrue("Ok fail", mustFail);
            checkException(e, CBORObject.STDERR_FLOAT_RANGE);
        }
    }

    void float16Test(String asText, String hex, boolean mustFail) {
        double v = Double.valueOf(asText);
        CBORObject cborObject = parseCborHex(hex);
        try {
            if (cborObject instanceof CBORNonFinite) return;
            float f = cborObject.getFloat16();
            assertFalse("Should fail", mustFail);
            assertTrue("Comp", v == f);
        } catch (Exception e) {
            assertTrue("Ok fail", mustFail);
            checkException(e, CBORObject.STDERR_FLOAT_RANGE);
        }
    }

    void compareToTest(int expected, CBORObject a, CBORObject b) {
        int result = a.compareTo(b);
        assertTrue("-", (expected < 0) == (result < 0));
        assertTrue("+", (expected > 0) == (result > 0));
        assertTrue("=", (expected == 0) == (result == 0));
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
        assertTrue("upd-0", 
            cborArray.update(1, new CBORString("hi")).getArray().get(1).getInt16() == 3);
        assertTrue("upd-1", cborArray.get(1).getString().equals("hi"));
        textCompare(cborArray,
               "[1, \"hi\", [4, 5]]");

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

        CBORMap cborMap = 
            new CBORMap()
                .set(new CBORInt(2), new CBORString("two"))
                .set(new CBORInt(0), new CBORString("zero"));
        assertTrue("upd-1", cborMap.update(
            new CBORInt(2), new CBORFloat(3.0), true).getString().equals("two"));
        assertTrue("upd-2", cborMap.get(new CBORInt(2)).getFloat64() == 3.0);
        assertTrue("upd-3", cborMap.update(
            new CBORInt(2), new CBORFloat(2.0), false).getFloat64() == 3.0);
        assertTrue("upd-4", cborMap.get(new CBORInt(2)).getFloat64() == 2.0);
        assertTrue("upd-3", cborMap.update(
            new CBORInt(1), new CBORString("one"), false) == null);
        assertTrue("upd-4", cborMap.get(new CBORInt(1)).getString().equals("one"));
        binaryCompare(cborMap, "a300647a65726f01636f6e6502f94000");
        binaryCompare(cborMap.merge(new CBORMap()
                        .set(new CBORInt(-1), new CBORString("m1"))
                        .set(new CBORInt(-2), new CBORString("m2"))),
                        "a500647a65726f01636f6e6502f9400020626d3121626d32");

        CBORTag cborTag = new CBORTag(800, new CBORString("tag"));
        assertTrue("upd-1", cborTag.update(new CBORFloat(34.0)).getString().equals("tag"));
        assertTrue("upd-2", cborTag.get().getFloat16() == 34.0);

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
       // integerTest(-1,                  false, true,     "3bffffffffffffffff");
        
        integerTest("-9223372036854775808",  IntegerVariations.INT64, false);
        integerTest("-9223372036854775809",  IntegerVariations.INT64, true);
        integerTest("9223372036854775807",   IntegerVariations.INT64, false);
        integerTest("9223372036854775808",   IntegerVariations.INT64, true);
        integerTest("-18446744073709551616", IntegerVariations.INT64, true);
        integerTest("-18446744073709551617", IntegerVariations.INT64, true);
        integerTest("18446744073709551616",  IntegerVariations.INT64, true);

        integerTest("18446744073709551615",  IntegerVariations.UINT64, false);
        integerTest("0",                     IntegerVariations.UINT64, false);
        integerTest("18446744073709551615",  IntegerVariations.UINT64, false);
        integerTest("18446744073709551616",  IntegerVariations.UINT64, true);
        integerTest("-1",                    IntegerVariations.UINT64, true);

        integerTest("-2147483648", IntegerVariations.INT32, false);
        integerTest("-2147483649", IntegerVariations.INT32, true);
        integerTest("2147483647",  IntegerVariations.INT32, false);
        integerTest("2147483648",  IntegerVariations.INT32, true);

        integerTest("-2147483649", IntegerVariations.UINT32, true);
        integerTest("4294967295",  IntegerVariations.UINT32, false);
        integerTest("4294967296",  IntegerVariations.UINT32, true);

        integerTest("-32768", IntegerVariations.INT16, false);
        integerTest("-32769", IntegerVariations.INT16, true);
        integerTest("32767",  IntegerVariations.INT16, false);
        integerTest("32768",  IntegerVariations.INT16, true);

        integerTest("-2",    IntegerVariations.UINT16, true);
        integerTest("65535", IntegerVariations.UINT16, false);
        integerTest("65536", IntegerVariations.UINT16, true);
        
        integerTest("-128",  IntegerVariations.INT8, false);
        integerTest("-129",  IntegerVariations.INT8, true);
        integerTest("127",   IntegerVariations.INT8, false);
        integerTest("128",   IntegerVariations.INT8, true);

        integerTest("-2",  IntegerVariations.UINT8, true);
        integerTest("255", IntegerVariations.UINT8, false);
        integerTest("256", IntegerVariations.UINT8, true);
        
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

        intBigintTest("0", "00", false);
        intBigintTest("-1", "20", false);
        intBigintTest("-9223372036854775808", "3b7fffffffffffffff", false);
        intBigintTest("-9223372036854775809", "3b8000000000000000", true);
        intBigintTest("-18446744073709551616", "3bffffffffffffffff", true);
        intBigintTest("18446744073709551615", "1bffffffffffffffff", false);
 
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
        
        float32Test("NaN",                    "F97E00",             false);
        float32Test("0.0",                    "F90000",             false);
        float32Test("3.4028234663852886e+38", "FA7F7FFFFF",         false);
        float32Test("3.4028234663852889e+38", "FB47EFFFFFE0000001", true);

        float16Test("NaN",                    "F97E00",             false);
        float16Test("0.0",                    "F90000",             false);
        float16Test("65504.0",                "F97BFF",             false);
        float16Test("3.4028234663852886e+38", "FA7F7FFFFF",         true);
        float16Test("3.4028234663852889e+38", "FB47EFFFFFE0000001", true);

        assertTrue("Tag", new CBORTag(5, new CBORString("hi"))
                        .equals(parseCborHex("C5626869")));
        
        assertFalse("comp", parseCborHex("C5626869").equals(null));
        assertFalse("comp", parseCborHex("C5626869").equals("jj"));
        assertTrue("comp", parseCborHex("C5626869").equals(parseCborHex("C5626869")));

        CBORInt compA = new CBORInt(1);
        CBORInt compB = new CBORInt(255);
        compareToTest(0, compA, compA);
        compareToTest(-1, compA, compB);
        compareToTest(1, compB, compA);

        getBigIntegerTest("-1", -1, false);
        getBigIntegerTest("-9223372036854775808", -9223372036854775808L, false);
        getBigIntegerTest("18446744073709551615", -1, true);

        assertTrue("dyn", new CBORMap().setDynamic((wr) -> {
            wr.set(new CBORInt(1), new CBORBoolean(true));
            return wr;
        }).get(new CBORInt(1)).getBoolean());

    }
 
    void getBigIntegerTest(String numeberString, long value, boolean unsigned) {
        BigInteger bValue = new BigInteger(numeberString);
        CBORInt cborInt = new CBORInt(value, unsigned);
        assertTrue("bi", bValue.equals(cborInt.getBigInteger()));
        assertTrue("bi", bValue.equals(CBORDecoder.decode(cborInt.encode()).getBigInteger()));
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
        CBORDecoder.decode(cborMap.encode());
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
            CBORObject removed = m.getKeys().get(m.size() - 1);
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
        preSortTest(new CBORMap().setSortingMode(false),
                    new CBORMap().setSortingMode(false),
                    false);
        preSortTest(new CBORMap().setSortingMode(true), 
                    new CBORMap().setSortingMode(true), 
                    true);
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
    public void openSSLPublicKey() throws Exception {
        assertTrue ("EdEc", KeyFactory.getInstance("Ed25519")
            .generatePublic(new X509EncodedKeySpec(new byte[] 
            {(byte)0x30, (byte)0x2a, (byte)0x30, (byte)0x05,
             (byte)0x06, (byte)0x03, (byte)0x2b, (byte)0x65,
             (byte)0x70, (byte)0x03, (byte)0x21, (byte)0x00,
             (byte)0xec, (byte)0x44, (byte)0xfe, (byte)0xf2,
             (byte)0x44, (byte)0x2a, (byte)0x1a, (byte)0x4c,
             (byte)0x75, (byte)0xed, (byte)0x1a, (byte)0x07,
             (byte)0x55, (byte)0x12, (byte)0x27, (byte)0xe0, 
             (byte)0x5f, (byte)0x0b, (byte)0x5e, (byte)0xfc,
             (byte)0x1e, (byte)0xfd, (byte)0xe8, (byte)0xb0, 
             (byte)0x6f, (byte)0xc2, (byte)0xc4, (byte)0xaf,
             (byte)0x1f, (byte)0x95, (byte)0xf5, (byte)0xe4})
        ) instanceof EdECPublicKey);
    }

    @Test
    public void bufferTest() throws Exception {
        byte[] cbor = HexaDecimal.decode(
   "782c74686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a792062656172");
        assertTrue("bt", 
                Arrays.equals(cbor,
                    new CBORDecoder(new StrangeReader(cbor), 0, Integer.MAX_VALUE)
                        .decodeWithOptions().encode()));

        assertTrue("bt", 
                Arrays.equals(cbor,
                    new CBORDecoder(new StrangeReader(cbor), 0, cbor.length)
                        .decodeWithOptions().encode()));
        try {
            new CBORDecoder(new ByteArrayInputStream(HexaDecimal.decode("7BFFFFFFFFFFFFFFFF00")), 
                            0,
                            Integer.MAX_VALUE)
                .decodeWithOptions();
            fail("Not valid");
        } catch (Exception e) {
            checkException(e, CBORDecoder.STDERR_N_RANGE_ERROR + "-1");
        }
        try {
            new CBORDecoder(new ByteArrayInputStream(HexaDecimal.decode("7AFFFFFFFF00")), 
                            0,
                            Integer.MAX_VALUE)
                .decodeWithOptions();
            fail("Not valid");
        } catch (Exception e) {
            checkException(e, CBORDecoder.STDERR_N_RANGE_ERROR + "4294967295");
        }
        try {
            new CBORDecoder(new ByteArrayInputStream(HexaDecimal.decode("797FFF00")),
                 0, 
                 100)
                .decodeWithOptions();
            fail("Not valid");
        } catch (Exception e) {
            checkException(e, CBORDecoder.STDERR_READING_LIMIT);
        }
        try {
            new CBORDecoder(new ByteArrayInputStream(HexaDecimal.decode("7A7FFFFFFF00")),
                            0,
                            Integer.MIN_VALUE)
                .decodeWithOptions();
            fail("Not valid");
        } catch (Exception e) {
            checkException(e, CBORDecoder.STDERR_READING_LIMIT);
        }
    }
 
    @Test
    public void accessTest() throws Exception {
        CBORObject cbor = parseCborHex("8301a40802183a032382f5f43859f6820405");
        try {
            ((CBORArray) cbor).get(0).getMap();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "Is type: CBORInt, requested: CBORMap");
        }

        try {
            ((CBORArray) cbor).get(1).getMap()
                    .get(new CBORInt(-91)).getInt32();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "Missing key: -91");
        }
 
        assertTrue("v1", ((CBORArray) cbor).get(1).getMap()
                .get(new CBORInt(58)).getInt32() == 3);

        assertTrue("v1", ((CBORArray) cbor).get(1).getMap()
                .getConditionally(new CBORInt(58), null).getInt32() == 3);

        assertTrue("v1", ((CBORArray) cbor).get(1).getMap()
                .getConditionally(new CBORString("no way"), new CBORInt(10)).getInt32() == 10);

        assertTrue("tag5", parseCborHex("C5626869").getTag().getTagNumber() == 5);
    }

    @Test
    public void unreadElementTest() throws Exception {
        CBORObject unread = null;
        try {
            unread = parseCborHex("8301a40802183a032382f5f43859f6820405");
            ((CBORArray) unread).get(0).getInt32();
            unread.checkForUnread();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Map key 8 with argument of type=CBORInt with value=2 was never read");
        }

        try {
            unread = parseCborHex("8301a40802183a032382f5f43859f6820405");
            unread = ((CBORArray) unread).get(1).getMap();
            ((CBORMap)unread).get(new CBORInt(8)).getInt32();
            ((CBORMap)unread).get(new CBORInt(58)).getInt32();
            ((CBORArray)((CBORMap)unread).get(new CBORInt(-4))).get(0).getBoolean();
            unread.checkForUnread();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Array element of type=CBORBoolean with value=false was never read");
        }
        
        try {
            unread = parseCborHex("C5626869");
            unread = ((CBORTag) unread).getTag().get();
            unread.checkForUnread();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Data of type=CBORString with value=\"hi\" was never read");
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
            ((CBORMap)unread).get(new CBORInt(8)).getInt32();
            ((CBORMap)unread).get(new CBORInt(58)).getInt32();
            ((CBORArray)((CBORMap)unread).get(new CBORInt(-4))).get(0).scan();
            unread.checkForUnread();
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Array element of type=CBORBoolean with value=false was never read");
        }

        // Getting an object without reading the value is considered as "unread".
        try {
            unread = parseCborHex("8301a40802183a032382f5f43859f6820405");
            unread = ((CBORArray) unread).get(1).getMap();
            ((CBORMap)unread).get(new CBORInt(8)).getInt32();
            ((CBORMap)unread).get(new CBORInt(58)).getInt32();
            ((CBORArray)((CBORMap)unread).get(new CBORInt(-4))).get(0);
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
                "Data of type=CBORInt with value=23 was never read");
        }

        try {
            unread = parseCborHex("A107666D7964617461");
            unread.checkForUnread();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Map key 7 with argument of type=CBORString with value=\"mydata\" was never read");
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
                "Is type: CBORInt, requested: CBORBoolean");
        }
        try {
            cborObject.getBytes();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Is type: CBORInt, requested: CBORBytes");
        }
        try {
            cborObject.getFloat64();  
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, 
                "Is type: CBORInt, requested: CBORFloat");
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
            checkException(e, CBORDecoder.STDERR_CBOR_EOF);
        }
        try {
            parseCborHex("a363666d74646e6f6e656761747453746d74a0686175746844617461590" +
                         "104292aad5fe5a8dc9a56429b2b0864f69124d11d9616ba8372e0c00215" +
                         "337be5bd410000000000000000000000000000000000000202d4db1c");
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, CBORDecoder.STDERR_READING_LIMIT);
        }
    }

    @Test
    public void deterministicEncodingTest() throws Exception {

        try {
            parseCborHex("3800");
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, CBORDecoder.STDERR_NON_DETERMINISTIC_N);
        }

        try {
            parseCborHex("c24900ffffffffffffffff");
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, CBORDecoder.STDERR_NON_DETERMINISTIC_BIGNUM);
        }

        try {
            parseCborHex("c24101");
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, CBORDecoder.STDERR_NON_DETERMINISTIC_BIGNUM);
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
                                         "fa7f810000"}) {
            try {
                parseCborHex(value);
                fail("must not execute" + value);
            } catch (Exception e) {
                checkException(e, 
                        e.getMessage().contains("float") ?
                    CBORDecoder.STDERR_NON_DETERMINISTIC_FLOAT
                                                           :
                e.getMessage().contains(CBORDecoder.STDERR_NON_DETERMINISTIC_NON_FINITE) ?
                    CBORDecoder.STDERR_NON_DETERMINISTIC_NON_FINITE :
                    CBORDecoder.STDERR_NON_DETERMINISTIC_N);
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
    
    CBORObject signAndVerify(CBORSigner<?> signer, 
                             CBORValidator<?> validator,
                             Long tagNumber,
                             String objectId) 
            throws IOException, GeneralSecurityException {
        CBORObject tbs = createDataToBeSigned();
        if (tagNumber != null) {
            tbs = tagNumber == CBORTag.RESERVED_TAG_COTX ?
                              new CBORTag(objectId, tbs) : new CBORTag(tagNumber, tbs);

            validator.setTagPolicy(CBORCryptoUtils.POLICY.MANDATORY, new CBORCryptoUtils.Collector() {
                
                @Override
                public void foundData(CBORObject objectOrNull) {
                    if (objectId == null) {
                        assertTrue("tagn", objectOrNull.getTag().getTagNumber() == tagNumber);
                    } else {
                        assertTrue("id", 
                                   objectOrNull.getTag()
                                       .get()
                                           .getArray()
                                               .get(0)
                                                   .getString().equals(objectId));
                        
                    }
                }
            });
        }

        CBORObject signedData = signer.sign(tbs);
        byte[] sd = signedData.encode();
        CBORObject cborSd = CBORDecoder.decode(sd);
        return validator.validate(cborSd);
     }

    CBORObject signAndVerify(CBORSigner<?> signer, CBORValidator<?> validator) 
            throws IOException, GeneralSecurityException {
        return signAndVerify(signer, validator, null, null);
    }

    void hmacTest(final int size, final HmacAlgorithms algorithm) throws IOException,
                                                                         GeneralSecurityException {
        CBORMap tbs = createDataToBeSigned();
        CBORObject res = new CBORHmacSigner(symmetricKeys.getValue(size),
                           algorithm).sign(tbs);
        byte[] sd = res.encode();
        CBORObject cborSd = CBORDecoder.decode(sd);
        new CBORHmacValidator(symmetricKeys.getValue(size)).validate(cborSd);
        
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
            
        }).sign(tbs);
        sd = res.encode();
        cborSd = CBORDecoder.decode(sd);
        new CBORHmacValidator(symmetricKeys.getValue(size)).validate(cborSd);

        tbs = createDataToBeSigned();
        CBORObject keyId = new CBORString(symmetricKeys.getName(size));
        res = new CBORHmacSigner(symmetricKeys.getValue(size), algorithm).setKeyId(keyId)
            .sign(tbs); 
        sd = res.encode();
        cborSd = CBORDecoder.decode(sd);
        new CBORHmacValidator(new HmacVerifierInterface() {

            @Override
            public boolean verify(byte[] data, 
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
                
        }).validate(cborSd);
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
                .setKeyId(keyId)
                .setPublicKey(p256.getPublic())
                .sign(createDataToBeSigned().getMap()); 
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, CBORCryptoUtils.STDERR_KEY_ID_PUBLIC);
        }
        
        // Testing the clone method
        CBORMap clone = createDataToBeSigned().getMap();
        CBORObject cloneSign = new CBORAsymKeySigner(p256.getPrivate())
            .setPublicKey(p256.getPublic())
            .setCloneMode(true)
            .sign(clone);
        assertFalse("c1", clone.containsKey(CSF_CONTAINER_LBL));
        new CBORAsymKeyValidator(p256.getPublic()).validate(cloneSign);
        cloneSign = new CBORAsymKeySigner(p256.getPrivate())
            .setPublicKey(p256.getPublic())
            .sign(clone);
            assertTrue("c2", clone.containsKey(CSF_CONTAINER_LBL));
        new CBORAsymKeyValidator(p256.getPublic()).validate(cloneSign);
        
        // HMAC signatures
        hmacTest(256, HmacAlgorithms.HMAC_SHA256);
        hmacTest(384, HmacAlgorithms.HMAC_SHA384);
        hmacTest(512, HmacAlgorithms.HMAC_SHA512);
        
        try {
            signAndVerify(new CBORAsymKeySigner(p256.getPrivate()), 
                    new CBORHmacValidator(new byte[] {9}));
            fail("must not execute");
        } catch (Exception e) {
            checkException(e, "Unknown COSE HMAC algorithm: -9");
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
        CBORSigner<?> tagSigner = new CBORAsymKeySigner(p256.getPrivate());
        
        CBORObject taggedSignature = tagSigner.sign(new CBORTag(objectId, createDataToBeSigned()));
        try {
            new CBORAsymKeyValidator(p256.getPublic()).validate(taggedSignature);
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
                                   .get()
                                       .getArray()
                                           .get(0)
                                               .getString().equals(objectId));
                }
            }).validate(taggedSignature);
        new CBORAsymKeyValidator(p256.getPublic())
            .setTagPolicy(CBORCryptoUtils.POLICY.MANDATORY, new CBORCryptoUtils.Collector() {
                
                @Override
                public void foundData(CBORObject objectOrNull) {
                    assertTrue("id", 
                               objectOrNull.getTag()
                                   .get()
                                       .getArray()
                                           .get(0)
                                               .getString().equals(objectId));
                }
            }).validate(taggedSignature);

        long tag = 18;
        // 1-dimensional tag
        tagSigner = new CBORAsymKeySigner(p256.getPrivate());
        
        taggedSignature = tagSigner.sign(new CBORTag(tag, createDataToBeSigned()));
        new CBORAsymKeyValidator(p256.getPublic())
            .setTagPolicy(CBORCryptoUtils.POLICY.MANDATORY, new CBORCryptoUtils.Collector() {
                
                @Override
                public void foundData(CBORObject objectOrNull) {
                    assertTrue("tagn", tag == objectOrNull.getTag().getTagNumber());
                }
            }).validate(taggedSignature);
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
                new CBORAsymKeyDecrypter.KeyLocator() {
 
                    @Override
                    public PrivateKey locate(PublicKey optionalPublicKey, 
                                             CBORObject optionalKeyId,
                                             KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                             ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
                        return compareKeyId(keyId, optionalKeyId) ? p256.getPrivate() : null;
                    }

                }).decrypt(p256EncryptedKeyId),
                dataToEncrypt));

        assertTrue("enc/dec", 
            Arrays.equals(new CBORAsymKeyDecrypter(
                new CBORAsymKeyDecrypter.DecrypterImpl() {

                    @Override
                    public byte[] decrypt(PublicKey optionalPublicKey, 
                                        CBORObject optionalKeyId,
                                        byte[] optionalEncryptedKey,
                                        PublicKey optionalEphemeralKey,
                                        KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                        ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
                        return EncryptionCore.receiverKeyAgreement(
                            true, 
                            compareKeyId(keyId, optionalKeyId) ? p256.getPrivate() : null, 
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
            checkException(e, "Map key -2 with argument of type=CBORInt with value=5 was never read");
        }
        try {
            CBORObject modified =  p256Encrypted;
            modified.getMap().get(CEF_KEY_ENCRYPTION_LBL).getMap().remove(CXF_ALGORITHM_LBL);
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
            Arrays.equals(new CBORX509Decrypter(new CBORX509Decrypter.KeyLocator() {

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
            }).decrypt(p256CertEncrypted), dataToEncrypt));
 
        assertTrue("enc/dec", 
            Arrays.equals(new CBORX509Decrypter(new CBORX509Decrypter.DecrypterImpl() {

                @Override
                public byte[] decrypt(X509Certificate[] certificatePath,
                                      byte[] optionalEncryptedKey,
                                      PublicKey optionalEphemeralKey,
                                      KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                      ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
                    assertTrue("cert", 
                               CBORCryptoUtils.encodeCertificateArray(certificatePath)
                                .equals(CBORCryptoUtils.encodeCertificateArray(p256CertPath)));
                    assertTrue("kea", keyEncryptionAlgorithm == 
                                        KeyEncryptionAlgorithms.ECDH_ES_A128KW);
                    assertTrue("cea", contentEncryptionAlgorithm == 
                                        ContentEncryptionAlgorithms.A256GCM);
                    return EncryptionCore.receiverKeyAgreement(true, 
                                                               p256.getPrivate(), 
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
                .setKeyId(new CBORString("illigal")).encrypt(dataToEncrypt);
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
                a256Encrypted.getMap().set(CEF_KEY_ENCRYPTION_LBL, 
                        new CBORMap().set(CXF_ALGORITHM_LBL,
                                new CBORInt(600))));
            fail("must not run");
        } catch (Exception e) {
            checkException(e, "Map key 1 with argument of type=CBORInt with value=600 was never read");
        }
        
        String objectId = "https://example.com/myobject";

        CBOREncrypter<?> taggedX25519Encrypter = new CBORAsymKeyEncrypter(x25519.getPublic(),
                                         KeyEncryptionAlgorithms.ECDH_ES_A256KW,
                                         ContentEncryptionAlgorithms.A256GCM)
            .setKeyId(new CBORString("mykey"))
            .setIntercepter(new CBORCryptoUtils.Intercepter() {
                
                @Override
                public CBORObject getCustomData() {
                    // Custom data as well
                    return new CBORArray().add(new CBORInt(500));
                }
                
            });
        CBORObject taggedX25519Encrypted = 
            taggedX25519Encrypter.encrypt(dataToEncrypt, new CBORTag(objectId, new CBORMap()));
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
                                           objectOrNull.getArray().get(0).getInt32() == 500);
                            }
                        })
                    .setTagPolicy(CBORCryptoUtils.POLICY.MANDATORY,
                                  new CBORCryptoUtils.Collector() {

                            @Override
                            public void foundData(CBORObject objectOrNull) {
                                assertTrue("id", 
                                           objectOrNull.getTag()
                                               .get()
                                                   .getArray()
                                                       .get(0)
                                                           .getString().equals(objectId));
                            }
                              
                        })
                    .decrypt(taggedX25519Encrypted), dataToEncrypt));
  
        taggedX25519Encrypter = new CBORAsymKeyEncrypter(x25519.getPublic(),
                                         KeyEncryptionAlgorithms.ECDH_ES_A256KW,
                                         ContentEncryptionAlgorithms.A256GCM)
            .setKeyId(new CBORString("mykey"));

        taggedX25519Encrypted = taggedX25519Encrypter.encrypt(dataToEncrypt,
                                                              new CBORTag(9999999, new CBORMap()));
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
                new CBORDecoder(new ByteArrayInputStream(HexaDecimal.decode(hexInput)),
                (sequenceFlag ? CBORDecoder.SEQUENCE_MODE : 0) |
                (acceptNonDeterministic ?
                    CBORDecoder.LENIENT_MAP_DECODING | CBORDecoder.LENIENT_NUMBER_DECODING : 0),
                                Integer.MAX_VALUE)
                    .decodeWithOptions().encode()).toUpperCase();
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
    
    @Test
    public void cborSequences() throws Exception {
        byte[] sequence = HexaDecimal.decode("00A104F58105A1056464617461");
        InputStream inputStream = new ByteArrayInputStream(sequence);
        int position = 0;
        CBORObject cborObject;
        CBORDecoder decoder = new CBORDecoder(inputStream,
                                              CBORDecoder.SEQUENCE_MODE,
                                              Integer.MAX_VALUE);
        while ((cborObject = decoder.decodeWithOptions()) != null) {
            byte[] rawCbor = cborObject.encode();
            assertTrue("Seq", Arrays.equals(rawCbor, 0, rawCbor.length, 
                                            sequence, position, position + rawCbor.length));
            position += rawCbor.length;
        }
        assertTrue("SeqEnd", sequence.length == position);
        assertTrue("SeqEnd2", decoder.getByteCount() == position);

        assertTrue("SeqNull", 
                   new CBORDecoder(new ByteArrayInputStream(new byte[0]),
                                   CBORDecoder.SEQUENCE_MODE,
                                   Integer.MAX_VALUE)
                       .decodeWithOptions() == null);
        CBORArray sequenceBuilder = new CBORArray()
            .add(new CBORString("Hello CBOR Sequence World!"))
            .add(new CBORArray()
                .add(new CBORFloat(4.5))
                .add(new CBORBoolean(true)));
        sequence = sequenceBuilder.encodeAsSequence();
        assertTrue("seqs", HexaDecimal.encode(sequence).equals(
            "781a48656c6c6f2043424f522053657175656e636520576f726c642182f94480f5"));

        inputStream = new ByteArrayInputStream(sequence);
        position = 0;
        decoder = new CBORDecoder(inputStream,
                                  CBORDecoder.SEQUENCE_MODE,
                                  Integer.MAX_VALUE);
        while ((cborObject = decoder.decodeWithOptions()) != null) {
            byte[] rawCbor = cborObject.encode();
            assertTrue("Seq", Arrays.equals(rawCbor, 0, rawCbor.length,
                                            sequence, position, position + rawCbor.length));
            position += rawCbor.length;
        }
        assertTrue("SeqEnd", sequence.length == position);
        assertTrue("SeqEnd2", decoder.getByteCount() == position);
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
                    "Map key \"key\" with argument of type=CBORString with value=\"value\" was never read");
            }
            try {
                cborPublicKey.set(new CBORString("key"), new CBORString("value"));
                CBORPublicKey.convert(cborPublicKey);
                fail("must not execute");
            } catch (Exception e) {
                checkException(e, 
                    "Map key \"key\" with argument of type=CBORString with value=\"value\" was never read");
            }
        }
    }
    
    public static class ObjectOne extends CBORTypedObjectDecoder {

        int number;
        
        static final String OBJECT_ID   = "https://example.com/object-1";
        static final CBORObject INT_KEY = new CBORInt(1);
        
        @Override
        protected void decode(CBORObject cborBody) {
            number = cborBody.getMap().get(INT_KEY).getInt32();
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
            number = cborBody.getMap().get(INT_KEY).getInt32();
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
            CBORDiagnosticNotation.convert(wrongs);
            fail("Should not");
        } catch (Exception e) {
            
        }
    }

    @Test
    public void diagnosticNotation() throws Exception {
        assertTrue("#",
                   CBORDiagnosticNotation.convert("# hi\r\n 1#commnt").getInt32() == 1);
        assertTrue("/",
                   CBORDiagnosticNotation.convert("/ comment\n /1").getInt32() == 1);
        String b64u = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        CBORObject decoded = CBORDiagnosticNotation.convert("b64'" + b64u + "'");
        assertTrue("b64u", b64u.equals(Base64URL.encode(decoded.getBytes())));
        String b64 = b64u.replace('-', '+').replace('_', '/');
        decoded = CBORDiagnosticNotation.convert("b64'" + b64 + "'");
        assertTrue("b64", b64u.equals(Base64URL.encode(decoded.getBytes())));
        assertTrue("dbl", CBORDiagnosticNotation.convert("3.5").getFloat64() == 3.5);
        assertTrue("int", CBORDiagnosticNotation.convert("1000").getInt32() == 1000);
        assertTrue("big", CBORDiagnosticNotation.convert(DIAG_BIG).getBigInteger().equals(
                new BigInteger(DIAG_BIG)));
        assertTrue("bigb", CBORDiagnosticNotation.convert(
                "0b" + DIAG_BIG).getBigInteger().equals(new BigInteger(DIAG_BIG, 2)));
        assertTrue("bigo", CBORDiagnosticNotation.convert(
                "0o" + DIAG_BIG).getBigInteger().equals(new BigInteger(DIAG_BIG, 8)));
        assertTrue("bigh", CBORDiagnosticNotation.convert(
                "0x" + DIAG_BIG).getBigInteger().equals(new BigInteger(DIAG_BIG, 16)));
        assertTrue("bigh-", CBORDiagnosticNotation.convert(
                "-0x" + DIAG_BIG).getBigInteger().equals(new BigInteger(DIAG_BIG, 16).negate()));
        assertTrue("hex", CBORDiagnosticNotation.convert(
                "-0x" + DIAG_HEX).getInt32() == -30);
        assertTrue("bstr", 
                    Arrays.equals(
                            CBORDiagnosticNotation.convert(
                                    "'" + DIAG_TEXT + "'").getBytes(),
                            DIAG_TEXT.getBytes("utf-8")));
        assertTrue("tstr", 
                   DIAG_TEXT.equals(CBORDiagnosticNotation.convert(
                           "\"" + DIAG_TEXT + "\"").getString()));
        assertTrue("tstr", 
                   DIAG_TEXT.equals(CBORDiagnosticNotation.convert(
                        "\"" + DIAG_TEXT.replace("te", "te\\\n") + "\"").getString()));
        assertTrue("emb", Arrays.equals(
                          CBORDiagnosticNotation.convert(
                                  "<< " + DIAG_CBOR.toString() + ">>").getBytes(),
                          DIAG_CBOR.encode()));
        Double v = CBORDiagnosticNotation.convert("Infinity").getExtendedFloat64();
        assertTrue("inf", v == Double.POSITIVE_INFINITY);
        v = CBORDiagnosticNotation.convert("-Infinity").getExtendedFloat64();
        assertTrue("-inf", v == Double.NEGATIVE_INFINITY);
        v = CBORDiagnosticNotation.convert("NaN").getExtendedFloat64();
        assertTrue("nan", v.isNaN());
        assertTrue("0.0", CBORDiagnosticNotation.convert("0.0").toString().equals("0.0"));
        assertTrue("-0.0", CBORDiagnosticNotation.convert("-0.0").toString().equals("-0.0"));
        ArrayList<CBORObject> seq = CBORDiagnosticNotation.convertSequence("1,\"" + DIAG_TEXT + "\"");
        assertTrue("seq", seq.size() == 2);
        assertTrue("seqi", seq.get(0).getInt32() == 1);
        assertTrue("seqs", seq.get(1).getString().equals(DIAG_TEXT));
        seq = CBORDiagnosticNotation.convertSequence("  ");
        assertTrue("seq", seq.size() == 0);
        
        diagFlag("0x ");
        diagFlag("056(8)");  // leading zero
        diagFlag("-56(8)");  // Neg
        CBORDiagnosticNotation.convert("18446744073709551615(8)");
        diagFlag("18446744073709551616(8)");  // Too large
        CBORDiagnosticNotation.convert("1.0e+300");
        diagFlag("1.0e+500");  // Too large
        diagFlag("b64'00'");  // Bad B64
        diagFlag("h'0'");  // Bad Hex
        diagFlag("6_0");  // _ not permitted here
        assertTrue("_", CBORDiagnosticNotation.convert("0b100_000000001").getInt32() == 2049);
        diagFlag("'unterminated");  // Bad string
        diagFlag("\"unterminated");  // Bad string
        
        String pretty = 
                "{\n" +
                "  1: \"text\\nnext\",\n" +
                "  2: [5.960465188081798e-8, h'abcdef', " + 
                "true, 0(\"2023-06-02T07:53:19Z\")]\n" +
                "}";
        
        CBORObject diag = CBORDiagnosticNotation.convert(pretty);
        assertTrue("diag1", pretty.equals(diag.toString()));
        assertTrue("diag2", pretty.replace(" ", "")
                                  .replace("\n", "").equals(diag.toDiagnosticNotation(false)));
        assertTrue("diag3", pretty.equals(diag.toDiagnosticNotation(true)));
        assertTrue("diag4", CBORDiagnosticNotation.convert("\"next\nline\r\\\ncont\r\nk\"")
            .toString().equals("\"next\\nline\\ncont\\nk\""));
    }

    void utf8DecoderTest(String hex, boolean ok) {
        byte[] cbor = HexaDecimal.decode(hex);
        try {
            byte[] roundTrip = CBORDecoder.decode(cbor).encode();
            assertTrue("OK", ok);
            assertTrue("Conv", Arrays.equals(cbor, roundTrip));
        } catch (Exception e) {
            assertFalse("No good", ok);
        }
    }

    void utf8EncoderTest(String string, boolean ok) {
         try {
            String encodedString = CBORDiagnosticNotation.convert(
                    "\"" + string + "\"").getString();
            assertTrue("OK", ok);
            assertTrue("Conv", string.equals(encodedString));
            byte[] encodedBytes = CBORDiagnosticNotation.convert(
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
    
    void compareHash(String s) {
        StringBuilder cbor = new StringBuilder();
        cbor.append((char)(0x60 + s.length()));
        for (char c : s.toCharArray()) {
            cbor.append(c);
        }
        assertTrue("hash=" + s, cbor.toString().hashCode() == new CBORString(s).hashCode());
    }

    @Test
    public void immutableKeys() {
        CBORArray immutableKey1 = new CBORArray();
        CBORArray immutableKey2 = new CBORArray();
        new CBORMap().set(immutableKey1, new CBORInt(4));
        try {
            immutableKey1.add(new CBORInt(6));
            fail("Must not!");
        } catch (Exception e) {
            checkException(e, CBORObject.STDERR_MAP_KEY_IMMUTABLE);
        }
        CBORArray mutableValue = new CBORArray();
        new CBORMap().set(new CBORInt(5), mutableValue);
        mutableValue.add(new CBORMap());
        new CBORMap().set(new CBORArray().add(immutableKey2), new CBORInt(5));
        try {
            immutableKey2.add(new CBORInt(6));
            fail("Must not!");
        } catch (Exception e) {
            checkException(e, CBORObject.STDERR_MAP_KEY_IMMUTABLE);
        }
        CBORArray k = new CBORArray();
        new CBORMap().set(k, new CBORInt(4));
        new CBORMap().set(k, new CBORInt(4));
    }
    
    @Test
    public void hashTest() {
        compareHash("");
        compareHash("7g#\".-iG");
        compareHash("r\u007fghhh");
    }

    void oneNonFiniteTurn(long value, String binexpect, String textexpect) {
        CBORNonFinite nonfinite = new CBORNonFinite(value);
        String text = nonfinite.toString();
        long returnValue = nonfinite.getNonFinite();
        long returnValue64 = nonfinite.getNonFinite64();
        CBORObject textdecode = CBORDiagnosticNotation.convert(textexpect);
        byte[] cbor = nonfinite.encode();
        byte[] refcbor = HexaDecimal.decode(binexpect);
        String hexbin = HexaDecimal.encode(cbor);
        assertTrue("eq1", text.equals(textexpect));
        assertTrue("eq2", hexbin.equals( binexpect));
        assertTrue("eq3", returnValue == ((CBORNonFinite)CBORDecoder.decode(cbor)).getNonFinite());
        assertTrue("eq4", returnValue == ((CBORNonFinite)textdecode).getNonFinite());
        assertTrue("eq5", CBORUtil.unsignedLongToByteArray(returnValue).length == nonfinite.length());
        assertTrue("eq7", CBORUtil.unsignedLongToByteArray(returnValue64).length == 8);
        assertTrue("eq8", nonfinite.equals(CBORDecoder.decode(cbor)));    
        assertTrue("eq9", ((returnValue64 &
            ((1L << CBORInternal.FLOAT64_SIGNIFICAND_SIZE) - 1L)) != 0) == nonfinite.isNaN());
        byte[] rawcbor = CBORUtil.unsignedLongToByteArray(value);
        rawcbor = CBORUtil.concatByteArrays(new byte[]{(byte)(0xf9 + (rawcbor.length >> 2))}, rawcbor);
        if (rawcbor.length > refcbor.length) {
            try {
            CBORDecoder.decode(rawcbor);
            fail("d1");
            } catch(Exception e) {
            assertTrue("d2", e.getMessage().contains("Non-deterministic"));
            }
        } else {
            CBORDecoder.decode(rawcbor);
        }
        assertTrue("d3", new CBORDecoder(new ByteArrayInputStream(rawcbor), CBORDecoder.LENIENT_NUMBER_DECODING, 100)
            .decodeWithOptions().equals(nonfinite));
        CBORNonFinite object = (CBORNonFinite)CBORDecoder.decode(refcbor);
        if (textexpect.contains("NaN") || textexpect.contains("Infinity")) {
            assertTrue("d4", String.valueOf(object.getExtendedFloat64()).equals(textexpect));
            assertTrue("d5", object.isSimple());
            assertTrue("d6", textexpect.contains("Infinity") ^ object.isNaN());
        } else {
            try {
            object.getExtendedFloat64();
            fail("d7");
            } catch (Exception e) {
            assertTrue("d8", e.getMessage().contains("7e00"));
            }
            assertFalse("d9", object.isSimple());
        }
    }

    void payloadOneTurn(long payload, String hex, String dn) {
        dn = dn == null ? "float'" + hex.substring(2) + "'" : dn;
        byte[] cbor = CBORNonFinite.createPayloadObject(payload).encode();
        CBORObject object = CBORDecoder.decode(cbor);
        assertTrue("plo1", object instanceof CBORNonFinite);
        CBORNonFinite nonFinite = (CBORNonFinite) object;
        assertTrue("plo2", nonFinite.getPayload() == payload);
        assertTrue("plo3", HexaDecimal.encode(cbor).equals(hex));
        assertTrue("plo4", nonFinite.toString().equals(dn));
        assertTrue("plo5", nonFinite.getNonFinite() == Long.valueOf(hex.substring(2), 16));
        assertFalse("plo6", nonFinite.getSign());
        String signedHex = hex.substring(0, 2) + "f" +hex.substring(3);
        nonFinite.setSign(true);
        assertTrue("plo7", nonFinite.getSign());
        assertTrue("plo8", HexaDecimal.encode(nonFinite.encode()).equals(signedHex));
        nonFinite = CBORNonFinite.createPayloadObject(payload).setSign(true);
        assertTrue("plo9", HexaDecimal.encode(nonFinite.encode()).equals(signedHex));
     //   System.out.printf("%13x  %18s  %s\n", payload, hex, dn);
      //  System.out.printf("<tr><td style='text-align:right'><code>%x</code></td><td style='text-align:right'><code>%s</code></td><td><code>%s</code></td></tr>\n", payload, hex, dn);
    }

    @Test
    public void nonFiniteValues() {
        oneNonFiniteTurn(0x7e00L,             "f97e00",             "NaN");
        oneNonFiniteTurn(0x7c01L,             "f97c01",             "float'7c01'");
        oneNonFiniteTurn(0xfc01L,             "f9fc01",             "float'fc01'");
        oneNonFiniteTurn(0x7fffL,             "f97fff",             "float'7fff'");
        oneNonFiniteTurn(0xfe00L,             "f9fe00",             "float'fe00'");
        oneNonFiniteTurn(0x7c00L,             "f97c00",             "Infinity");
        oneNonFiniteTurn(0xfc00L,             "f9fc00",             "-Infinity");

        oneNonFiniteTurn(0x7fc00000L,         "f97e00",             "NaN");
        oneNonFiniteTurn(0x7f800001L,         "fa7f800001",         "float'7f800001'");
        oneNonFiniteTurn(0xff800001L,         "faff800001",         "float'ff800001'");
        oneNonFiniteTurn(0x7fffffffL,         "fa7fffffff",         "float'7fffffff'");
        oneNonFiniteTurn(0xffc00000L,         "f9fe00",             "float'fe00'");
        oneNonFiniteTurn(0x7f800000L,         "f97c00",             "Infinity");
        oneNonFiniteTurn(0xff800000L,         "f9fc00",             "-Infinity");

        oneNonFiniteTurn(0x7ff8000000000000L, "f97e00",             "NaN");
        oneNonFiniteTurn(0x7ff0000000000001L, "fb7ff0000000000001", "float'7ff0000000000001'");
        oneNonFiniteTurn(0xfff0000000000001L, "fbfff0000000000001", "float'fff0000000000001'");
        oneNonFiniteTurn(0x7fffffffffffffffL, "fb7fffffffffffffff", "float'7fffffffffffffff'");
        oneNonFiniteTurn(0x7ff0000020000000L, "fa7f800001",         "float'7f800001'");
        oneNonFiniteTurn(0xfff0000020000000L, "faff800001",         "float'ff800001'");
        oneNonFiniteTurn(0xfff8000000000000L, "f9fe00",             "float'fe00'");
        oneNonFiniteTurn(0x7ff0040000000000L, "f97c01",             "float'7c01'");
        oneNonFiniteTurn(0x7ff0000000000000L, "f97c00",             "Infinity");
        oneNonFiniteTurn(0xfff0000000000000L, "f9fc00",             "-Infinity");

        // Very special, some platforms natively support NaN with payloads, but we don't care
        // "signaling" NaN
        double nanWithPayload = Double.longBitsToDouble(0x7ff0000000000001L);
        CBORNonFinite nonFinite = (CBORNonFinite)CBORFloat.createExtendedFloat(nanWithPayload);
        assertTrue("conv", nonFinite instanceof CBORNonFinite);
        assertTrue("truncated", nonFinite.getNonFinite64() == 0x7ff8000000000000L);              // Returns "quiet" NaN
        assertTrue("cbor",  HexaDecimal.encode(nonFinite.encode()).equals("f97e00"));   // Encoded as it should
        assertTrue("combined", Double.isNaN(nonFinite.getExtendedFloat64()));                    // It is a Double.NaN
        assertTrue("nan", nonFinite.isNaN());    
        
        payloadOneTurn(0, "f97c00", "Infinity");
        payloadOneTurn(1, "f97e00", "NaN");
        payloadOneTurn(2, "f97d00", null);
        payloadOneTurn((1L << FLOAT16_SIGNIFICAND_SIZE) - 1L, "f97fff", null);
        payloadOneTurn(1L << FLOAT16_SIGNIFICAND_SIZE,        "fa7f801000", null);
        payloadOneTurn((1L << FLOAT32_SIGNIFICAND_SIZE) - 1L, "fa7fffffff", null);
        payloadOneTurn(1L << FLOAT32_SIGNIFICAND_SIZE,        "fb7ff0000010000000", null);
        payloadOneTurn((1L << FLOAT64_SIGNIFICAND_SIZE) - 1L, "fb7fffffffffffffff", null);

        try {
            CBORNonFinite.createPayloadObject(1L << FLOAT64_SIGNIFICAND_SIZE).encode();
            fail("pl8");
        } catch(Exception e) {
            checkException(e, CBORNonFinite.STDERR_PAYLOAD_RANGE);
        }
    }

    void oneDateTime(long epoch, String isoString) {
        assertTrue("date1", new CBORString(isoString).getDateTime().getTimeInMillis() == epoch);
        CBORObject cbor = CBORDecoder.decode(new CBORString(isoString).encode());
        assertTrue("date2", cbor.getDateTime().getTimeInMillis() == epoch);
        assertTrue("date3", new CBORTag(0l, new CBORString(isoString))
            .getDateTime().getTimeInMillis() == epoch);
        assertTrue("date3", new CBORTag(1l, new CBORInt(epoch / 1000))
            .getEpochTime().getTimeInMillis() == epoch);
        assertTrue("date31", new CBORInt(epoch / 1000)
            .getEpochTime().getTimeInMillis() == epoch);
        assertTrue("date4", new CBORTag(1l, new CBORFloat(((double)epoch) / 1000))
            .getEpochTime().getTimeInMillis() == epoch);
        assertTrue("date5", new CBORTag(1l, new CBORFloat(((double)epoch + 3.0) / 1000))
            .getEpochTime().getTimeInMillis() == epoch + 3);
        assertTrue("date5", new CBORFloat(((double)epoch - 3.0) / 1000)
            .getEpochTime().getTimeInMillis() == epoch - 3);
    }

    @Test
    public void nonFiniteNethods() {
        byte[] cbor = CBORNonFinite.createPayloadObject(6).encode();
        assertTrue("nfa1", ((CBORNonFinite)CBORDecoder.decode(cbor)).getPayload() == 6);
    }

    void badDate(String hexBor, String err) {
        try {
            CBORDecoder.decode(Hex.decode(hexBor));
            fail("must not");
        } catch (Exception e) {
            checkException(e, err);
        }
    }

    void oneEpoch(String hexBor, double epoch, String err) {
        assertTrue("epoch1", CBORDecoder.decode(Hex.decode(hexBor))
            .getEpochTime().getTimeInMillis() == epoch * 1000);
        CBORObject date = CBORDecoder.decode(Hex.decode(hexBor));
        try {
            date.checkForUnread();
            fail("must not");
        } catch (Exception e) {
            checkException(e, err);
        }
        date.getEpochTime();
        date.checkForUnread();
    }

    @Test
    public void dateSystems() {
        oneDateTime(1740060548000l, "2025-02-20T14:09:08+00:00");
        oneDateTime(1740060548000l, "2025-02-20T14:09:08Z");
        oneDateTime(1740060548000l, "2025-02-20T15:09:08+01:00");
        oneDateTime(1740060548000l, "2025-02-20T15:39:08+01:30");
        oneDateTime(1740060548000l, "2025-02-20T12:09:08-02:00");
        oneDateTime(1740060548000l, "2025-02-20T11:39:08-02:30");
        badDate("c001", "Is type: CBORInt, requested: CBORString");
        badDate("c06135", "\"dateTime\" syntax error: 5");
        badDate("c16135", "Is type: CBORString, requested: CBORFloat");
        oneEpoch("FB41D9EDCDE113645A", 1740060548.303, "Data of type=CBORFloat");
        oneEpoch("c1FB41D9EDCDE113645A", 1740060548.303, "Tagged object 1 of type=CBORFloat");
        oneEpoch("00", 0, "Data of type=CBORInt");
    }

    @Test
    public void multiSignature() throws Exception {
        CBORObject o = new CBORAsymKeySigner(p256.getPrivate())
            .setMultiSignatureMode(true)
            .setPublicKey(p256.getPublic())
            .sign(createDataToBeSigned());
  //      System.out.println(o.toString());
        o = new CBORAsymKeySigner(ed25519.getPrivate())
            .setMultiSignatureMode(true)
            .setPublicKey(ed25519.getPublic())
            .sign(o);
   //     System.out.println(o.toString());
        int[] counter = new int[]{0};
        new CBORAsymKeyValidator(new CBORAsymKeyValidator.KeyLocator() {
            @Override
            public PublicKey locate(PublicKey optionalPublicKey, CBORObject optionalKeyId,
                    AsymSignatureAlgorithms algorithm) {
                counter[0]++;
                return algorithm == AsymSignatureAlgorithms.ED25519 ? 
                                                ed25519.getPublic() : p256.getPublic();
            }
        }).setMultiSignatureMode(true)
          .validate(o);
        assertTrue("nr", counter[0] == 2);
        try {
            new CBORAsymKeySigner(p256.getPrivate())
                .setPublicKey(p256.getPublic())
                .sign(o);
            fail("should not");
        } catch (Exception e) {
            checkException(e, "Duplicate key: simple(99)");
        }
        try {
        new CBORAsymKeyValidator(new CBORAsymKeyValidator.KeyLocator() {
            @Override
            public PublicKey locate(PublicKey optionalPublicKey, CBORObject optionalKeyId,
                    AsymSignatureAlgorithms algorithm) {
                counter[0]++;
                return algorithm == AsymSignatureAlgorithms.ED25519 ? 
                                                ed25519.getPublic() : p256.getPublic();
            }
        }).setMultiSignatureMode(true)
          .validate(parseCborHex("a2017348656c6c6f207369676e656420776f726c6421f86380"));
        } catch (Exception e) {
            checkException(e, "No signature found");
        }
    }

    @Test
    public void circularTest() throws Exception {
        CBORMap m = new CBORMap();
        m.set(new CBORInt(1), m);
        try {
            m.encode();
            fail("Must not");
        } catch (StackOverflowError e) {
        }
    }
 }
