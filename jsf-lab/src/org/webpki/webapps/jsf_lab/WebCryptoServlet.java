/*
 *  Copyright 2018-2020 WebPKI.org (http://webpki.org).
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
package org.webpki.webapps.jsf_lab;

import java.io.IOException;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;

import org.webpki.json.JSONCryptoHelper;

public class WebCryptoServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {

        StringBuilder html = new StringBuilder(
                "<form name=\"shoot\" method=\"POST\" action=\"validate\">" +
                "<input type=\"hidden\" " + 
                "id=\"" + ValidateServlet.JSF_OBJECT + "\" " +
                "name=\"" + ValidateServlet.JSF_OBJECT + "\">" +
                "<input type=\"hidden\" " +
                "id=\"" + ValidateServlet.JSF_VALIDATION_KEY + "\" " +
                "name=\"" + ValidateServlet.JSF_VALIDATION_KEY + "\">" +
                "<input type=\"hidden\" " +
                "name=\"" + ValidateServlet.JSF_SIGN_LABL + "\" " +
                "value=\"" + CreateServlet.DEFAULT_SIG_LBL + "\">" +
                "</form>" +
                "<div class=\"header\">WebCrypto / JWS-JCS Demo</div>" +
                "<div style=\"display:flex;justify-content:center;padding-top:15pt\"><div>" +
                "This demo only relies on ES6 and WebCrypto features and " +
                "does not refer to any external libraries either.</div></div>" +
                "<div style=\"display:flex;justify-content:center\">" +
                "<div class=\"stdbtn\" onclick=\"createKey()\">" +
                "Create RSA Key Pair" +
                "</div>" +
                "</div>" +
                "<div id=\"pub.key\" style=\"padding-top:10pt\"></div>");

        StringBuilder js = new StringBuilder(
                "var pubKey;\n" + 
                "var privKey;\n" + 
                "var jsonObject;\n" + 
                "var publicKeyInJWKFormat; // The bridge between JSF and WebCrypto\n\n" + 
                "//////////////////////////////////////////////////////////////////////////\n" + 
                "// Utility methods                                                      //\n" + 
                "//////////////////////////////////////////////////////////////////////////\n" + 
                "var BASE64URL_ENCODE = [" + 
                "'A','B','C','D','E','F','G','H'," + 
                "'I','J','K','L','M','N','O','P'," + 
                "'Q','R','S','T','U','V','W','X'," + 
                "'Y','Z','a','b','c','d','e','f'," + 
                "'g','h','i','j','k','l','m','n'," + 
                "'o','p','q','r','s','t','u','v'," + 
                "'w','x','y','z','0','1','2','3'," + 
                "'4','5','6','7','8','9','-','_'];\n" + 
                "function convertToBase64URL(binarray) {\n" + 
                "    var encoded = new String ();\n" + 
                "    var i = 0;\n" + 
                "    var modulo3 = binarray.length % 3;\n" + 
                "    while (i < binarray.length - modulo3) {\n" + 
                "        encoded += BASE64URL_ENCODE[(binarray[i] >>> 2) & 0x3F];\n" + 
                "        encoded += BASE64URL_ENCODE[((binarray[i++] << 4) & 0x30) | ((binarray[i] >>> 4) & 0x0F)];\n" + 
                "        encoded += BASE64URL_ENCODE[((binarray[i++] << 2) & 0x3C) | ((binarray[i] >>> 6) & 0x03)];\n" + 
                "        encoded += BASE64URL_ENCODE[binarray[i++] & 0x3F];\n" + 
                "    }\n" + 
                "    if (modulo3 == 1) {\n" + 
                "        encoded += BASE64URL_ENCODE[(binarray[i] >>> 2) & 0x3F];\n" + 
                "        encoded += BASE64URL_ENCODE[(binarray[i] << 4) & 0x30];\n" + 
                "    }\n" + 
                "    else if (modulo3 == 2) {\n" + 
                "        encoded += BASE64URL_ENCODE[(binarray[i] >>> 2) & 0x3F];\n" + 
                "        encoded += BASE64URL_ENCODE[((binarray[i++] << 4) & 0x30) | ((binarray[i] >>> 4) & 0x0F)];\n" + 
                "        encoded += BASE64URL_ENCODE[(binarray[i] << 2) & 0x3C];\n" + 
                "    }\n" + 
                "    return encoded;\n" + 
                "}\n\n" + 
                "function convertToUTF8(string) {\n" + 
                " var buffer = [];\n" + 
                " for (var i = 0; i < string.length; i++) {\n" + 
                "   var c = string.charCodeAt(i);\n" + 
                "   if (c < 128) {\n" + 
                "     buffer.push(c);\n" + 
                "   } else if ((c > 127) && (c < 2048)) {\n" + 
                "     buffer.push((c >> 6) | 0xC0);\n" + 
                "     buffer.push((c & 0x3F) | 0x80);\n" + 
                "   } else {\n" + 
                "     buffer.push((c >> 12) | 0xE0);\n" + 
                "     buffer.push(((c >> 6) & 0x3F) | 0x80);\n" + 
                "     buffer.push((c & 0x3F) | 0x80);\n" + 
                "   }\n" + 
                " }\n" + 
                " return new Uint8Array(buffer);\n" + 
                "}\n\n" + 
                "//////////////////////////////////////////////////////////////////////////\n" + 
                "// Nice-looking text-boxes                                              //\n" + 
                "//////////////////////////////////////////////////////////////////////////\n" + 
                "function fancyJSONBox(header, json) {\n" + 
                "  return '<div style=\"padding-bottom:3pt\">' + header + ':</div><div class=\"staticbox\">' + " +
                   "JSON.stringify(json, null, '  ')" +
                   ".replace(/&/g,'&amp;')" +
                   ".replace(/</g,'&lt;')" +
                   ".replace(/>/g,'&gt;')" +
                   ".replace(/\\n/g,'<br>')" +
                   ".replace(/  /g,'&nbsp;&nbsp;&nbsp;&nbsp;') + '</div>';\n" + 
                "}\n\n" + 
                "//////////////////////////////////////////////////////////////////////////\n" + 
                "// Error message helper                                                 //\n" + 
                "//////////////////////////////////////////////////////////////////////////\n" + 
                "function bad(id, message) {\n" + 
                " document.getElementById (id).innerHTML = '<b style=\"color:red\">' + message + '</b>';\n" + 
                "}\n\n" + 
                "//////////////////////////////////////////////////////////////////////////\n" + 
                "// Create key event handler                                             //\n" + 
                "//////////////////////////////////////////////////////////////////////////\n" + 
                "function createKey() {\n" + 
                "  if (window.crypto === undefined || window.crypto.subtle == undefined) {\n" + 
                "    document.location.href = 'nowebcrypto';\n" + 
                "    return;\n" + 
                "  }\n" + 
                "  console.log('Begin creating key...');\n" + 
                "  document.getElementById('pub.key').innerHTML = '<i>Working...</i>';\n" + 
                "  crypto.subtle.generateKey({name: 'RSASSA-PKCS1-v1_5', hash: {name: 'SHA-256'}, modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01])},\n" + 
                "                            false, ['sign', 'verify']).then(function(key) {\n" + 
                "    pubKey = key.publicKey;\n" + 
                "    privKey = key.privateKey;\n\n" + 
                "    crypto.subtle.exportKey('jwk', pubKey).then(function(key) {\n" + 
                "      publicKeyInJWKFormat = key;\n" + 
                "      console.log('generateKey() RSASSA-PKCS1-v1_5: PASS');\n" + 
                "      document.getElementById('pub.key').innerHTML = fancyJSONBox('Generated public key in JWK format', publicKeyInJWKFormat) + " + 
                "'<div style=\"padding-bottom:3pt;padding-top:10pt\">Editable sample data in JSON Format:</div>" + 
                "<textarea class=\"textbox\" " + 
                "rows=\"5\" maxlength=\"10000\" id=\"json.text\">" + 
                "{\\n" +
                "  &quot;statement&quot;: &quot;Hello signed world!&quot;,\\n" +
                "  &quot;otherProperties&quot;: [2e3, true]\\n" + "}" +
                "</textarea>" + 
                "<div style=\"display:flex;justify-content:center;padding-bottom:10pt\">" +
                "<div class=\"stdbtn\" onclick=\"signSampleData()\">" +
                "Sign Sample Data" +
                "</div>" +
                "</div>" +
                "<div id=\"sign.res\"><div>';\n" + 
                "    });\n" + 
                "  }).then(undefined, function() {\n" + 
                "    bad('pub.key', 'WebCrypto failed for unknown reasons');\n" + 
                "  });" + 
                "\n}\n\n" + 
                "//////////////////////////////////////////////////////////////////////////\n" +
                "// Canonicalizer                                                        //\n" +
                "//////////////////////////////////////////////////////////////////////////\n" +
                "var canonicalize = function(object) {\n" +
                "\n" +
                "    var buffer = '';\n" +
                "    serialize(object);\n" +
                "    return buffer;\n" +
                "\n" +
                "    function serialize(object) {\n" +
                "        if (object !== null && typeof object === 'object') {\n" +
                "            if (Array.isArray(object)) {\n" +
                "                buffer += '[';\n" +
                "                let next = false;\n" +
                "                // Array - Maintain element order\n" +
                "                object.forEach((element) => {\n" +
                "                    if (next) {\n" +
                "                buffer += ',';\n" +
                "                    }\n" +
                "                    next = true;\n" +
                "                    // Recursive call\n" +
                "                    serialize(element);\n" +
                "                });\n" +
                "                buffer += ']';\n" +
                "            } else {\n" +
                "                buffer += '{';\n" +
                "                let next = false;\n" +
                "                // Object - Sort properties before serializing\n" +
                "                Object.keys(object).sort().forEach((property) => {\n" +
                "                    if (next) {\n" +
                "                buffer += ',';\n" +
                "                    }\n" +
                "                    next = true;\n" +
                "                    // Properties are just strings - Use ES6\n" +
                "                    buffer += JSON.stringify(property);\n" +
                "                    buffer += ':';\n" +
                "                    // Recursive call\n" +
                "                    serialize(object[property]);\n" +
                "                });\n" +
                "                buffer += '}';\n" +
                "            }\n" +
                "        } else {\n" +
                "            // Primitive data type - Use ES6\n" +
                "            buffer += JSON.stringify(object);\n" +
                "        }\n" +
                "    }\n" +
                "};\n\n" + 
                "//////////////////////////////////////////////////////////////////////////\n" + 
                "// Sign event handler                                                   //\n" + 
                "//////////////////////////////////////////////////////////////////////////\n" + 
                "function signSampleData() {\n" + 
                "  try {\n" + 
                "    document.getElementById('sign.res').innerHTML = '';\n" + 
                "    jsonObject = JSON.parse(document.getElementById('json.text').value);\n" + 
                "    if (typeof jsonObject !== 'object' || Array.isArray(jsonObject)) {\n" + 
                "      bad('sign.res', 'Only JSON objects can be signed');\n" + 
                "      return;\n" + 
                "    }\n" + 
                "    if (jsonObject." + 
                CreateServlet.DEFAULT_SIG_LBL + 
                ") {\n" + 
                "      bad('sign.res', 'Object is already signed');\n" + 
                "      return;\n" + 
                "    }\n" + 
                "    var jsfSignature = {};\n" + 
                "    jsonObject." + CreateServlet.DEFAULT_SIG_LBL + " = jsfSignature;\n" +
                "    jsfSignature." + 
                JSONCryptoHelper.ALGORITHM_JSON + 
                " = '" + 
                AsymSignatureAlgorithms.RSA_SHA256.getAlgorithmId(AlgorithmPreferences.JOSE) + 
                "';\n" + 
                "    var publicKeyObject = {};\n" + 
                "    jsfSignature." + JSONCryptoHelper.PUBLIC_KEY_JSON + " = publicKeyObject;\n" +
                "    publicKeyObject." + 
                JSONCryptoHelper.KTY_JSON + 
                " = '" + 
                JSONCryptoHelper.RSA_PUBLIC_KEY + 
                "';\n" + 
                "    publicKeyObject." + 
                JSONCryptoHelper.N_JSON + 
                " = publicKeyInJWKFormat." + 
                JSONCryptoHelper.N_JSON + 
                ";\n" + 
                "    publicKeyObject." + 
                JSONCryptoHelper.E_JSON + 
                " = publicKeyInJWKFormat." + 
                JSONCryptoHelper.E_JSON + 
                ";\n" + 
                "  } catch (err) {\n" + 
                "    bad('sign.res', 'JSON error: ' + err.toString());\n" + 
                "    return;\n" + 
                "  }\n" + 
                "  crypto.subtle.sign({name: 'RSASSA-PKCS1-v1_5'}, privKey,\n" + 
                "                     convertToUTF8(canonicalize(jsonObject))).then(function(signature) {\n" + 
                "    console.log('Sign with RSASSA-PKCS1-v1_5 - SHA-256: PASS');\n" + 
                "    document.getElementById('" + 
                   ValidateServlet.JSF_VALIDATION_KEY + 
                "').value = JSON.stringify(publicKeyObject);\n" +
                "    jsfSignature." + 
                JSONCryptoHelper.VALUE_JSON + 
                " = convertToBase64URL(new Uint8Array(signature));\n" + 
                "    document.getElementById('" + ValidateServlet.JSF_OBJECT +
                "').value = JSON.stringify(jsonObject);\n" +
                "    document.getElementById('sign.res').innerHTML = fancyJSONBox('Signed data in JSF format', jsonObject) + '" + 
                "<div style=\"display:flex;justify-content:center\">" +
                "<div class=\"stdbtn\" onclick=\"verifySignatureOnServer()\">" +
                "Validate Signature (on the server)" +
                "</div>" +
                "</div>';\n" + 
                "  }).then(undefined, function() {\n" + 
                "    bad('sign.res', 'WebCrypto failed for unknown reasons');\n" + 
                "  });\n" + 
                "}\n\n" + 
                "//////////////////////////////////////////////////////////////////////////\n" + 
                "// Optional validation is in this demo/test happening on the server     //\n" + 
                "//////////////////////////////////////////////////////////////////////////\n" + 
                "function verifySignatureOnServer() {\n" + 
                "  document.forms.shoot.submit();\n" +
                "}\n");

        HTML.standardPage(response, js.toString(), html);
    }
}
