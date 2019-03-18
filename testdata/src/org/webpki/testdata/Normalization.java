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
package org.webpki.testdata;

import java.io.File;

import java.io.IOException;

import java.security.KeyPair;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONAsymKeySigner;
import org.webpki.json.JSONAsymKeyVerifier;
import org.webpki.json.JSONCryptoHelper;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;
import org.webpki.json.NumberToJSON;

import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;

/*
 * Create JCN test data
 */
public class Normalization {
    static String baseKey;
    static String baseData;
    static String baseNormalization;
    
    static String keyId;
    
    static String EURO_SYMBOL ="\\u20ac";
    
    static StringBuilder result = new StringBuilder("Input data:\n\n");
    
    static void addRFC(String value) {
        result.append("\n\nRFC Input:\n\n<t><figure align=\"center\">" +
                      "<artwork><![CDATA[")
              .append(value)
              .append("]]></artwork></figure></t>");
    }
   
    static KeyPair readJwk(String keyType) throws Exception {
        JSONObjectReader jwkPlus = JSONParser.parse(ArrayUtil.readFile(baseKey + keyType + "privatekey.jwk"));
        // Note: The built-in JWK decoder does not accept "kid" since it doesn't have a meaning in JCS or JEF. 
        if ((keyId = jwkPlus.getStringConditional("kid")) != null) {
            jwkPlus.removeProperty("kid");
        }
        return jwkPlus.getKeyPair();
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            throw new Exception("Wrong number of arguments");
        }
        baseKey = args[0] + File.separator;
        baseData = args[1] + File.separator;
        baseNormalization = args[2] + File.separator;
        byte[] dataToBeNormalized = ArrayUtil.readFile(baseData + "jsonobjecttobenormalized.json");
        JSONParser.setStrictNumericMode(false);
        JSONObjectReader jsonNumbers1 = JSONParser.parse(ArrayUtil.readFile(baseData + "jsonnumbers.json"));
        JSONArrayReader jsonNumbers = jsonNumbers1.getJSONArrayReader();
        result.append(new String(dataToBeNormalized, "utf-8"));
        addRFC(new String(dataToBeNormalized, "utf-8"));
        JSONObjectReader parsed = JSONParser.parse(dataToBeNormalized);
        String normalizedRaw = parsed.serializeToString(JSONOutputFormats.NORMALIZED);
        result.append(normalizedRaw).append("\n\n");
        String normalizedRfc = normalizedRaw.replace("\u20ac", EURO_SYMBOL);
        int i = normalizedRfc.indexOf("ers\"") + 5;
        addRFC(normalizedRfc.substring(0, i) + '\n' + normalizedRfc.substring(i));
        result.append("\n<t>Note: "+ EURO_SYMBOL + " denotes the Euro character, " +
                            "which not being ASCII, is currently not displayable in RFCs.</t>\n\n\n");   
        boolean next = false;
        result.append('\n');
        int byteCount = 0;
        for (byte b : parsed.serializeToBytes(JSONOutputFormats.NORMALIZED)) {
            if (byteCount++ % 20 == 0) {
                result.append('\n');
                next = false;
            }
            if (next) {
                result.append(" ");
            }
            next = true;
            result.append(DebugFormatter.getHexString(new byte[]{b}));
        }
        result.append("\n\n\n");
        StringBuilder table = new StringBuilder(
           "|===================================================================|\n" +
           "|   ES6 Internal   |   JSON Representation    |       Comment       |\n" +
           "|===================================================================|");
        while (jsonNumbers.hasMore()) {
            JSONObjectReader set = jsonNumbers.getObject();
            String jsonRepresentation = "";
            Double number = Double.longBitsToDouble(Long.parseUnsignedLong(set.getString("ieee"), 16));
            if (!number.isNaN() && !number.isInfinite()) {
                jsonRepresentation = NumberToJSON.serializeNumber(number);
                if (!set.getString("json").equals(jsonRepresentation)) {
                    throw new IOException(jsonRepresentation + "@" + set.getString("json"));
                }
            }
            int q = jsonRepresentation.length();
            while (q++ < 24) {
                jsonRepresentation += " ";
            }
            String comment = set.getStringConditional("comment", "");
            q = comment.length();
            while (q++ < 19) {
                comment += " ";
            }
            table.append("\n| ")
                 .append(set.getString("ieee").toLowerCase())
                 .append(" | ")
                 .append(jsonRepresentation)
                 .append(" | ")
                 .append(comment)
                 .append(" |\n" +
            "|-------------------------------------------------------------------|");
        }
        jsonNumbers1.checkForUnread();

        addRFC(table.toString());
        KeyPair keyPair = readJwk("p256");
        byte[] signature = new JSONObjectWriter(parsed)
            .setSignature(new JSONAsymKeySigner(keyPair.getPrivate(), keyPair.getPublic(), null))
                  .serializeToBytes(JSONOutputFormats.NORMALIZED);
        JSONParser.parse(signature).getSignature(new JSONCryptoHelper.Options())
            .verify(new JSONAsymKeyVerifier(keyPair.getPublic()));
        ArrayUtil.writeFile(baseNormalization + "result.txt", result.toString().getBytes("utf-8"));
        System.out.println(result);
   }
      
}