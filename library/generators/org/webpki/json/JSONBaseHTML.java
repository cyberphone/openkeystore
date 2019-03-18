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
package org.webpki.json;

import java.io.File;
import java.io.IOException;

import java.net.URLEncoder;

import java.util.LinkedHashMap;
import java.util.TreeSet;
import java.util.Vector;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.CryptoAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.MACAlgorithms;

import org.webpki.util.ArrayUtil;

/**
 * Supports HTML descriptions of JSON protocols.
 * 
 * @author Anders Rundgren
 */
public class JSONBaseHTML  {
    public static final String MANDATORY               = "M";
    public static final String OPTIONAL                = "O";
    
    public static final String PAGE_WIDTH              = "1000pt";
    public static final String NON_SKS_ALGORITHM_COLOR = "#A0A0A0";
    
    public static final String CHAPTER_FONT_SIZE       = "14pt";

    public static final String SECTION_FONT_SIZE       = "14pt";
    
    public static final String HEADER_STYLE            = "font-size:28pt;font-family:'Times New Roman',Times,Serif";
    
    public static final String ARRAY_SUBSCRIPT         = "<span style=\"position:relative;bottom:-0.5em;font-size:.9em\">&thinsp;";

    public static final String REQUIRED_COLUMN         = "Req";
    
    public static final String REF_JSON                = "RFC7159";
    
    public static final String REF_X509                = "RFC5280";

    public static final String REF_XMLDSIG             = "XMLDSIG";
    
    public static final String REF_XMLENC              = "XMLENC";
    
    public static final String REF_ES6                 = "ES6";
    
    public static final String REF_V8                  = "V8";
    
    public static final String REF_JCS                 = "JCS";

    public static final String REF_JEF                 = "JEF";

    public static final String REF_JWS                 = "RFC7515";

    public static final String REF_JWE                 = "RFC7516";

    public static final String REF_JWK                 = "RFC7517";

    public static final String REF_JWA                 = "RFC7518";
    
    public static final String REF_BASE64              = "RFC4648";
    
    public static final String REF_PEM                 = "RFC7468";
    
    public static final String REF_URI                 = "RFC3986";

    public static final String REF_DSKPP               = "RFC6063";

    public static final String REF_SKS                 = "SKS";

    public static final String REF_CMP                 = "RFC4210";

    public static final String REF_WEB_CRYPTO          = "WCRYPT";

    public static final String REF_LDAP_NAME           = "RFC4514";

    public static final String REF_PKCS8               = "RFC5208";

    public static final String REF_BRAINPOOL           = "RFC5639";
    
    public static final String REF_FIPS186             = "FIPS-186-4";

    public static final String REF_WEBPKI_FOR_ANDROID  = "PKIDROID";

    public static final String REF_OPENKEYSTORE        = "OPENKEY";

    public static final String REF_SATURN              = "SATURN";

    public static final String REF_YASMIN              = "YASMIN";

    public static final String REF_WEBIDL              = "WEBIDL";
    
    public static final String JCS_PUBLIC_KEY_RSA      = "Additional RSA Properties";

    public static final String JCS_PUBLIC_KEY_EC       = "Additional EC Properties";

    public static final String REMOTE_KEY_EXAMPLE      = "remotekeyexample";
    public static final String REMOTE_CERT_EXAMPLE     = "remotecertexample";
    public static final String EXTENSION_EXAMPLE       = "extensionexample";
    public static final String EXCLUSION_EXAMPLE       = "exclusionexample";

    String file_name;
    String subsystem_name;
    
    class Reference {
        String html_description;
        boolean referenced;
    }
    
    LinkedHashMap<String, Reference> references = new LinkedHashMap<String, Reference>();
    
    class TOCEntry {
        String link;
        boolean indented;
        boolean appendix;
        int sequence;
        boolean prefix_on;
        int sub_seq;
        boolean italic;

        public String getPrefix() {
            StringBuilder buffer = new StringBuilder();
            if (prefix_on) {
                if (appendix) {
                    buffer.append("Appendix ").append(
                            (char) (('A' - 1) + sequence));
                } else {
                    buffer.append(String.valueOf(sequence));
                }
                if (indented) {
                    buffer.append(".").append(String.valueOf(sub_seq));
                }
                buffer.append(appendix ? ':' : '.').append("&nbsp;");
            }
            return buffer.toString();
        }

        String PrefixPlusLink() {
            return prefix_on ? "<td style=\"text-align:right\"><a href=\"#"
                    + link + "\">" + getBeginItalic() + getPrefix()
                    + getEndItalic() + "</a></td>" : "";
        }

        private String getEndItalic() {
            return italic ? "</i>" : "";
        }

        private String getBeginItalic() {
            return italic ? "<i>" : "";
        }

        public int remainingColums() {
            boolean prefix_on_flag = false;
            boolean indent_flag = false;
            for (String toc_entry : toc.keySet()) {
                TOCEntry te = toc.get(toc_entry);
                if (te.appendix == appendix) {
                    if (te.indented) {
                        indent_flag = true;
                        if (te.prefix_on) {
                            prefix_on_flag = true;
                        }
                    }
                }
            }
            return (indented || !indent_flag) ? (prefix_on || !prefix_on_flag) ? 1
                    : 2
                    : prefix_on_flag ? 3 : 2;
        }
    }

    LinkedHashMap<String, TOCEntry> toc = new LinkedHashMap<String, TOCEntry>();

    int curr_toc_seq = 0;

    boolean appendix_mode;

    boolean arrays_found;

    String externalWebReference(String url) {
        return "<a target=\"_blank\" title=\"External link opened in a new window\" href=\""
                + url
                + "\"><span style=\"white-space: nowrap\">"
                + url
                + "</span></a>";
    }

    StringBuilder external_styles = new StringBuilder();

    String fileReaderBase1;
    String fileReaderBase2;
    String fileReaderBase3;

    public void addGlobalStyle(String style) {
        external_styles.append(style);
    }
    
    public byte[] readFile1(String name) throws IOException {
        return readFile(fileReaderBase1, name);
    }
    
    public byte[] readFile2(String name) throws IOException {
        return readFile(fileReaderBase2, name);
    }
    
    public byte[] readFile3(String name) throws IOException {
        return readFile(fileReaderBase3, name);
    }

    public JSONObjectReader readJson1(String name) throws IOException {
        return JSONParser.parse(readFile1(name));
    }

    public JSONObjectReader readJson2(String name) throws IOException {
        return JSONParser.parse(readFile2(name));
    }

    byte[] readFile(String fileReaderBase, String name) throws IOException {
        if (fileReaderBase == null) {
            throw new IOException("File reader base missing!");
        }
        return ArrayUtil.readFile(fileReaderBase + name);
    }

    public JSONBaseHTML(String[] args, String subsystem_name) throws IOException {
        file_name = args[0];
        this.subsystem_name = subsystem_name;
        if (args.length > 1) {
            fileReaderBase1 = args[1] + File.separator;
        }
        if (args.length > 2) {
            fileReaderBase2 = args[2] + File.separator;
        }
        if (args.length > 3) {
            fileReaderBase3 = args[3] + File.separator;
        }

        addReferenceEntry(REF_JSON,
            "T. Bray, \"The JavaScript Object Notation (JSON) Data Interchange Format\"" +
            ", RFC&nbsp;7159, March&nbsp;2014.");

        addReferenceEntry(REF_URI,
            "T. Berners-Lee, R. Fielding, L. Masinter, \"Uniform " +
            "Resource Identifier (URI): Generic Syntax\", RFC&nbsp;3986, January&nbsp;2005.");

        addReferenceEntry(REF_XMLDSIG,
            "D. Eastlake, J. Reagle, D. Solo, F. Hirsch, M. Nystrom, T. Roessler, K. Yiu, " +
            "\"XML Signature Syntax and Processing Version 1.1.\", W3C Recommendation, " +
            "April&nbsp;2013. <br>" +
            externalWebReference ("https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/"));

        addReferenceEntry(REF_XMLENC,
            "\"XML Encryption Syntax and Processing\", J. Reagle, " +
            "D. Eastlake, April&nbsp;2013. " +
            externalWebReference ("https://www.w3.org/TR/xmlenc-core1/"));

        addReferenceEntry(REF_WEB_CRYPTO,
            "\"Web Cryptography API\", R. Sleevi, " +
            "M. Watson, W3C&nbsp;Candidate&nbsp;Recommendation, December&nbsp;2014. " +
            externalWebReference ("https://www.w3.org/TR/WebCryptoAPI/"));

        addReferenceEntry(REF_JCS,
            "A. Rundgren, \"JCS - JSON Cleartext Signature\", Work in progress, " +
            "<span style=\"white-space: nowrap\">V0.80, January&nbsp;2018.</span> " +
            externalWebReference ("https://cyberphone.github.io/doc/security/jose-jcs.html"));

        addReferenceEntry(REF_YASMIN,
                "A. Rundgren, \"YASMIN - Yet Another jSon Message notatIoN\", Work in progress, " +
                "<span style=\"white-space: nowrap\">V0.6, April&nbsp;2017.</span> " +
                externalWebReference ("https://cyberphone.github.io/doc/web/yasmin.html"));

        addReferenceEntry(REF_JEF,
            "A. Rundgren, \"JEF - JSON Encryption Format\", Work in progress, " +
            "<span style=\"white-space: nowrap\">V0.60, January&nbsp;2018.</span> " +
            externalWebReference ("https://cyberphone.github.io/doc/security/jose-jef.html"));

        addReferenceEntry(REF_SKS, "A. Rundgren, \"Secure Key Store (SKS) - API and Architecture\", Work in progress, " +
            "<span style=\"white-space: nowrap\">V1.03, May&nbsp;2017.</span> " +
            externalWebReference ("https://cyberphone.github.io/doc/security/sks-api-arch.pdf"));

        addReferenceEntry(REF_WEBPKI_FOR_ANDROID, "\"WebPKI Suite\", " +
            externalWebReference ("https://play.google.com/store/apps/details?id=org.webpki.mobile.android"));

        addReferenceEntry(REF_OPENKEYSTORE, "\"OpenKeyStore Project\", " +
            externalWebReference ("https://github.com/cyberphone/openkeystore"));

        addReferenceEntry(REF_SATURN, "\"Saturn Project\", " +
            externalWebReference ("https://github.com/cyberphone/saturn"));

        addReferenceEntry(REF_WEBIDL, "C. McCormack, " +
            "\"Web IDL\", W3C Candidate Recommendation, " +
            "April&nbsp;2012. <br>" +
            externalWebReference ("https://www.w3.org/TR/2012/CR-WebIDL-20120419/"));

        addReferenceEntry(REF_ES6, "A. Wirfs-Brock, " +
            "\"ECMAScript 2015 Language Specification\", ECMA-262, " +
            "June&nbsp;2015. <br>" +
            externalWebReference ("https://www.ecma-international.org/ecma-262/6.0/ECMA-262.pdf"));

        addReferenceEntry(REF_V8,
            "\"Chrome V8\", Google Chrome JavaScript Engine, " +
            externalWebReference ("https://developers.google.com/v8/"));

        addReferenceEntry(REF_JWS,
           "M. Jones, J. Bradley, N. Sakimura, \"JSON Web Signature (JWS)\", " +
           "RFC&nbsp;7515, May&nbsp;2015.");

        addReferenceEntry(REF_JWE,
            "M. Jones, J. Hildebrand, \"JSON Web Encryption (JWE)\", " +
            "RFC&nbsp;7516, May&nbsp;2015.");

        addReferenceEntry(REF_JWK,
            "M. Jones, \"JSON Web Key (JWK)\", " +
            "RFC&nbsp;7517, May&nbsp;2015.");

        addReferenceEntry(REF_JWA,
            "M. Jones, \"JSON Web Algorithms (JWA)\", " +
            "RFC&nbsp;7518, May&nbsp;2015.");

        addReferenceEntry(REF_X509,
            "D. Cooper, S. Santesson, S. Farrell, S. Boeyen, " +
            "R. Housley, W. Polk, \"Internet X.509 Public Key " +
            "Infrastructure Certificate and Certificate Revocation List " +
            "(CRL) Profile\", RFC&nbsp;5280, May&nbsp;2008.");

        addReferenceEntry(REF_BASE64,
            "S. Josefsson, \"The Base16, Base32, and Base64 Data " +
            "Encodings\", RFC&nbsp;4648, October&nbsp;2006.");

        addReferenceEntry(REF_PEM,
            "S. Josefsson, S. Leonard, \"Textual Encodings of PKIX, PKCS, and CMS Structures\", " +
            "RFC&nbsp;7468, April&nbsp;2015.");

        addReferenceEntry(REF_DSKPP,
            "A. Doherty, M. Pei, S. Machani, M. Nystrom, " +
            "\"Dynamic Symmetric Key Provisioning Protocol (DSKPP)\", " +
            "RFC&nbsp;6063, December&nbsp;2010.");

        addReferenceEntry(REF_CMP, "C. Adams, S. Farrell, T. Kause, T. Mononen, " +
             "\"Internet X.509 Public Key Infrastructure Certificate Management Protocol (CMP)\", " +
             "RFC&nbsp;4210, September&nbsp;2005.");

        addReferenceEntry(REF_LDAP_NAME, "K. Zeilenga, " +
            "\"Lightweight Directory Access Protocol (LDAP): String Representation of Distinguished Names\", " +
            "RFC&nbsp;4514, June&nbsp;2006.");

        addReferenceEntry(REF_PKCS8,
            "B. Kaliski, \"Public-Key Cryptography Standards (PKCS) #8: " +
            "Private-Key Information Syntax Specification Version 1.2\", " +
            "RFC&nbsp;5208, May&nbsp;2008.");

        addReferenceEntry(REF_BRAINPOOL, "M. Lochter, J. Merkle, " +
            "\"Elliptic Curve Cryptography (ECC) Brainpool Standard Curves and Curve Generation\", " +
            "RFC&nbsp;5639, March&nbsp;2010.");

        addReferenceEntry(REF_FIPS186,
            "\"FIPS PUB 186-4: Digital Signature Standard (DSS)\", " +
            "U.S. Department of Commerce/National Institute of Standards and Technology, June&nbsp;2013. " +
            externalWebReference("http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf"));
      }

    JSONBaseHTML () {}
    
    public static class Types {

        public enum WEBPKI_DATA_TYPES {

            ANY     ("any", "&quot;any&quot;",                            null,
                     "Arbitrary JSON type or object"),

            BOOLEAN ("bool",   "<code>true|false</code>", null,
                     "Boolean"),
                     
            BYTE    ("byte",   "<i>number</i>",                           null,
                     "Unsigned byte"),
                     
            SHORT   ("short",  "<i>number</i>",                           null,
                     "Signed two-byte integer"),
                     
            USHORT  ("ushort",  "<i>number</i>",                          null,
                     "Unsigned two-byte integer"),

            INT     ("int",    "<i>number</i>",                           null,
                     "Signed four-byte integer"),

            INT53   ("int53",  "<i>number</i>",                           null,
                     "Signed 53-bit integer"),

            UINT    ("uint",    "<i>number</i>",                          null,
                     "Unsigned four-byte integer"),

            DOUBLE  ("double",  "<i>number</i>",                          null,
                     "64-bit IEEE floating point value"),

            BIGINT  ("bigint", "<i>string</i>",                           null,
                    "Base10-encoded integer with arbitrary precision"),

            BIGDEC  ("decimal", "<i>string</i>",                          null,
                     "Decimal type compatible with Java BigDecimal"),

            STRING  ("string", "<i>string</i>",                           null,
                     "Arbitrary string"),

            URI     ("uri",    "<i>string</i>",                           REF_URI,
                     "URI <a href=\"#Reference." + REF_URI + "\">[" + REF_URI + "]</a>"),

            ID      ("id",     "<i>string</i>",                           null,
                     "Identifier which <b>must</b> consist of 1-32 characters, where each " +
                     "character is in the range <code>'!'</code> - <code>'~'</code> (0x21 - 0x7e)."),

            BYTE_ARRAY  ("byte[]", "<i>string</i>",                       REF_BASE64,
                     "Base64URL-encoded <a href=\"#Reference." + REF_BASE64 + "\">[" + REF_BASE64 + "]</a> binary data"),
                     
            BYTE_ARRAY2  ("byte2[]", "<i>string</i>",                       REF_BASE64,
                      "Base64-encoded <a href=\"#Reference." + REF_BASE64 + "\">[" + REF_BASE64 + "]</a> binary data"),

            CRYPTO  ("crypto", "<i>string</i>",                           null,
                     "Base64URL-encoded positive integer with arbitrary precision. " +
                     "Note that the value <b>must not</b> contain <i>leading</i> zero-valued bytes"),
                     
            TIME    ("time",   "<i>string</i>",                           null,
                     "Date-time string in ISO format <code>YYYY-MM-DDThh:mm:ss{ms}tz</code> " +
                     "where <code>ms</code> is an <i>optional</i> field consisting of <code>'.'</code> followed by 1-3 digits, while " +
                     "<code>tz</code> is either <code>'Z'</code> or <code>&#x00b1;hh:mm</code>."),
                     
            OBJECT  ("object", "<code>{}</code>",                         null,
                     "JSON object"),

            SPECIAL ("n/a", "",                                           null,
                    "Special construct, see documentation.");

            String data_type;
            String json;
            String ref;
            String description;
            boolean used;

            WEBPKI_DATA_TYPES(String data_type, String json, String ref, String description) {
                this.data_type = data_type;
                this.json = json;
                this.ref = ref;
                this.description = description;
                used = false;
            }

            public String getDataType() {
                return data_type;
            }

            public String getJSON() {
                return json;
            }

            public String getRef() {
                return ref;
            }

            public String getDescription() {
                return description;
            }

            public void setUsed() {
                used = true;
            }

            public boolean isUsed() {
                return used;
            }
          }

        public static final String CERTIFICATE_PATH  = "Certificate Path";
        public static final String PROPERTY_LIST     = "Property List";
        public static final String URI_LIST          = "List of URIs";
        public static final String LINE_SEPARATOR    = "<div style=\"height:6pt;padding:0px\"></div>";
      }
    
    abstract class Content {
        abstract String getHTML() throws IOException;
        
        Content() {
            division_objects.add(this);
        }
    }
  
    class DataTypesTable extends Content {

        static final String DATA_TYPES = "Data Types";
        
        static final String LINK_PREFIX = "Datatype.";

        DataTypesTable() {
            super();
        }

        @Override
        String getHTML () throws IOException {
            StringBuilder buffer = new StringBuilder("<table class=\"tftable\" style=\"margin-top:10pt\">" +
                      "<tr><th>Type</th><th>Mapping</th><th>Description</th></tr>");
            for (Types.WEBPKI_DATA_TYPES type : Types.WEBPKI_DATA_TYPES.values()) {
                if (type.isUsed()) {
                    buffer.append("<tr id=\"" + LINK_PREFIX)
                     .append(type.getDataType())
                     .append("\"><td style=\"text-align:center\">")
                     .append(type.getDataType())
                     .append("</td><td style=\"text-align:center\">")
                     .append(type.getJSON())
                     .append("</td><td>")
                     .append(type.getDescription())
                     .append("</td></tr>");
                }
            }
            return buffer.append("</table>" +  (arrays_found ? "<div>Note that &quot;Type&quot; refers to the element type for arrays." + Types.LINE_SEPARATOR + "</div>" : Types.LINE_SEPARATOR)).toString();
        }
    }

    class DataTypeDescription extends Content {
        DataTypeDescription() {
            super();
        }

        @Override
        String getHTML() throws IOException {
            return new StringBuilder(
                    "<div style=\"padding:0\">JSON objects are described as tables with associated properties. When a property holds a JSON object this is denoted by a <a href=\"#Notation\">link</a> to the actual definition. " + Types.LINE_SEPARATOR +
                    "Properties may either be <i>mandatory</i> (" + MANDATORY + ") or <i>optional</i> (" + OPTIONAL + ") as defined in the &quot;" + REQUIRED_COLUMN + "&quot; column." + Types.LINE_SEPARATOR +
                    (arrays_found? "Array properties are identified by [&thinsp;]" + JSONBaseHTML.ARRAY_SUBSCRIPT  + "x-y</span> where the range expression represents the valid number of array elements. " + Types.LINE_SEPARATOR : "") +
                    "In some JSON objects there is a choice " +
                    "from a set of <i>mutually exclusive</i> alternatives.<br>This is manifested in object tables like the following:" +
                    "<table class=\"tftable\" style=\"font-style:italic;margin-top:10pt;margin-bottom:5pt\">" +
                    "<tr><td>Property selection 1</td><td>Type selection 1</td><td rowspan=\"2\">Req</td><td>Comment selection 1</td></tr>" +
                    "<tr><td>Property selection 2</td><td>Type selection 2</td><td>Comment selection 2</td></tr>" +
                    "</table></div>").toString();
        }
    }

    class Paragraph extends Content {
        StringBuilder local_html;
       
        Paragraph() {
            super();
        }
        
        @Override
        String getHTML() throws IOException {
            return local_html.append("</div>").toString();
        }
    }

    class ProtocolTable extends Content {
        ProtocolTable() {
            super();
        }

        @Override
        String getHTML() throws IOException {
            StringBuilder buffer = new StringBuilder("<table class=\"tftable\" style=\"width:" + PAGE_WIDTH + "\">");
            for (ProtocolObject protocol_object : protocol_objects) {
                buffer.append(protocol_object.getObjectHTML());
            }
            return buffer.append("</table>").toString();
        }
    }

    class References extends Content {
        References() {
            super();
        }

        @Override
        String getHTML() throws IOException {
            StringBuilder buffer = new StringBuilder("<table class=\"tftable\" style=\"width:600pt\"><tr><th>Reference</th><th>Description</th></tr>");
            for (String reference : new TreeSet<String>(references.keySet()).toArray (new String[0])) {
                Reference r = references.get (reference);
                if (r.referenced) {
                    buffer.append("<tr><td id=\"")
                     .append("Reference.")
                     .append(reference)
                     .append("\" style=\"white-space:nowrap\">")
                     .append(brackit(reference))
                     .append("</td><td>")
                     .append(r.html_description)
                     .append("</td></tr>");
                }
            }
            return buffer.append("</table>").toString();
        }
    }

    class TOC extends Content {
        TOC() {
            super();
        }

        @Override
        String getHTML () throws IOException {
            StringBuilder buffer = new StringBuilder("<div><span style=\"font-size:" + 
                CHAPTER_FONT_SIZE + ";font-family:arial,verdana,helvetica\">" +
                "Table of Contents</span>" +
                "<table style=\"margin-left:20pt;margin-top:5pt\">");
            boolean new_tab = true;
            for (String toc_entry : toc.keySet()) {
                if (toc.get(toc_entry).appendix && new_tab) {
                    new_tab = false;
                    buffer.append("</table><table style=\"margin-left:20pt;margin-top:5pt\">");
                }
                TOCEntry te = toc.get(toc_entry);
                buffer.append("<tr style=\"white-space: nowrap\">")
                 .append(te.indented ? "<td></td><td style=\"width:15pt\"></td>" : te.PrefixPlusLink())
                 .append(te.indented ? te.PrefixPlusLink() : "")
                 .append("<td colspan=\"")
                 .append(te.remainingColums())
                 .append("\"><a href=\"#")
                 .append(te.link)
                 .append("\">")
                 .append(te.getBeginItalic())
                 .append(toc_entry)
                 .append(te.getEndItalic())
                 .append("</a></td></tr>");
            }
            return buffer.append("</table></div>").toString();
        }
    }

    public static String codeVer(String string, int width) {
        StringBuilder s = new StringBuilder("<code>").append(string);
        int i = string.length();
        while (i++ <= width) {
            s.append("&nbsp;");
        }
        return s.append("</code>").toString();
    }

    public static class ProtocolStep {
        String json_file;
        String optional_table_comment_HTML;

        public ProtocolStep(String json_file) {
            this(json_file, null);
        }

        public ProtocolStep(String json_file, String optional_table_comment_HTML) {
            System.out.println("Sample: " + json_file);
            this.json_file = json_file;
            this.optional_table_comment_HTML = optional_table_comment_HTML;
        }

    }

    public interface Extender {
        ProtocolObject.Row.Column execute(ProtocolObject.Row.Column column) throws IOException;
    }

    public interface RowInterface {
        ProtocolObject.Row newRow();
    }

    public class ProtocolObject implements RowInterface {
        String protocols[];
        boolean main_object;
        String notes;
        
        Vector<Row> rows = new Vector<Row>();
        
        public class Row {
            Vector<Column> columns = new Vector<Column>();
            boolean set_group;
            int depth;
            String property_link;
            String header;
            
            public class Column implements RowInterface {
                StringBuilder column = new StringBuilder();
                Row parent;
                
                Column (Row parent) {
                    columns.add(this);
                    this.parent = parent;
                }

                public Column newColumn() {
                    if (rows.lastElement().columns.size () == 2 && rows.lastElement().columns.lastElement().column.length () ==  0) {
                        rows.lastElement().columns.lastElement().column.append("string");
                    }
                    if (rows.lastElement().columns.size () == 3 && rows.lastElement().columns.lastElement().column.length () ==  0) {
                        rows.lastElement().columns.lastElement().column.append(MANDATORY);
                    }
                    return rows.lastElement().newColumn();
                }

                @Override
                public Row newRow() {
                    return new Row();
                }

                public Column addString(String string) throws IOException {
                    if (columns.size() == 2) {
                        throw new IOException(
                                "Cannot set string data for column #2");
                    }
                    if (columns.size() == 3) {
                        throw new IOException(
                                "Cannot set string data for column #3");
                    }
                    column.append(string);
                    return this;
                }

                public Column addContext(String argument) throws IOException {
                    keyWord(JSONDecoderCache.CONTEXT_JSON,
                            JSONObjectWriter.htmlKeywordColor, true);
                    return keyWord(argument, JSONObjectWriter.htmlStringColor,
                            false);
                }

                public Column addQualifier(String argument) throws IOException {
                    keyWord(JSONDecoderCache.QUALIFIER_JSON,
                            JSONObjectWriter.htmlKeywordColor, true);
                    return keyWord(argument, JSONObjectWriter.htmlStringColor,
                            false);
                }

                private Column keyWord(String string, String color, boolean property) throws IOException {
                    code();
                    quote();
                    addString("<span style=\"color:");
                    addString(color);
                    if (property) {
                        parent.property_link = makeLink(protocols[0])
                                + "."
                                + (string.charAt(0) == '@' ? string.substring(1) : string);
                    }
                    addString("\">");
                    addString(string);
                    addString("</span>");
                    quote();
                    if (property) {
                        addString(":&nbsp;");
                    }
                    nocode();
                    return this;
                }

                private void nocode() throws IOException {
                    addString("</code>");
                }

                private void code() throws IOException {
                    addString("<code>");
                }

                private void quote() throws IOException {
                    addString("&quot;");
                }

                public Column addProperty(String property) throws IOException {
                    return keyWord(property, JSONObjectWriter.htmlPropertyColor, true);
                }

                public Column addSymbolicValue(String symbol_value)
                        throws IOException {
                    code();
                    quote();
                    nocode();
                    addString("<i>").addString(symbol_value).addString("</i>");
                    code();
                    quote();
                    nocode();
                    return this;
                }

                public Column addArrayList(String symbol_value, int array_min)
                        throws IOException {
                    leftArray();
                    addSymbolicValue(symbol_value);
                    rightArray(array_min);
                    return this;
                }

                public Column setUsage(boolean mandatory) throws IOException {
                    if (columns.size() != 3) {
                        throw new IOException(
                                "This method only applies to column #3");
                    }
                    column.append(mandatory ? MANDATORY : OPTIONAL);
                    return this;
                }

                public Column setType(Types.WEBPKI_DATA_TYPES type)
                        throws IOException {
                    if (columns.size() != 2) {
                        throw new IOException(
                                "This method only applies to column #2");
                    }
                    if (type.getRef() != null) {
                        createReference(type.getRef());
                    }
                    if (type != Types.WEBPKI_DATA_TYPES.SPECIAL) {
                        type.setUsed();
                    }
                    column.append(type.getDataType());
                    return this;
                }

                public Column addArrayLink(String link, int array_min)
                        throws IOException {
                    arrays_found = true;
                    leftArray();
                    link(link, link,
                            " style=\"margin-left:2pt;margin-right:2pt;\"");
                    rightArray(array_min);
                    return this;
                }

                private void rightArray(int array_min) throws IOException {
                    addString("]<span style=\"position:relative;bottom:-0.5em;font-size:.9em\">&thinsp;"
                            + array_min + "-n</span>");
                }

                private void leftArray() throws IOException {
                    if (columns.size() != 1) {
                        throw new IOException(
                                "This method only applies to column #2");
                    }
                    addString("[");
                }

                private void link(String href, String name, String style)
                        throws IOException {
                    addString("<a href=\"#").addString(makeLink(href))
                            .addString("\"").addString(style).addString(">")
                            .addString(makeName(name)).addString("</a>");
                }

                public Column addLink(String name) throws IOException {
                    link(name, name, "");
                    return this;
                }

                public Column addDataTypeLink(Types.WEBPKI_DATA_TYPES type)
                        throws IOException {
                    link(DataTypesTable.LINK_PREFIX + type.getDataType(),
                            type.getDataType(), "");
                    return this;
                }

                public Column addPropertyLink(String property, String holding_object) throws IOException {
                    link(holding_object + "." + property, property, "");
                    return this;
                }

                public Column addValue(String value) throws IOException {
                    keyWord(value, JSONObjectWriter.htmlStringColor, false);
                    return this;
                }

                public Column addUnquotedValue(String unquoted_value)
                        throws IOException {
                    return addString("<i>").addString(unquoted_value)
                            .addString("</i>");
                }

                public Column setChoice(boolean mandatory, int depth)
                        throws IOException {
                    setUsage(mandatory);
                    parent.depth = depth;
                    parent.set_group = true;
                    return this;
                }

                public Column newExtensionRow(Extender extender)
                        throws IOException {
                    return extender.execute(this);
                }

                public Column setNotes(String notes) throws IOException {
                    if (notes != null) {
                        protocol_objects.lastElement().setNotes(notes);
                    }
                    return this;
                }

                public Row newRow(String header) {
                    Row row = newRow();
                    row.header = header;
                    return row;
                }
            }
            
            Row() {
                rows.add(this);
            }

            public Column newColumn() {
                return new Column(this);
            }
        }

        ProtocolObject(String[] protocols, boolean main_object) {
            protocol_objects.add(this);
            this.protocols = protocols;
            this.main_object = main_object;
        }

        String getObjectHTML() throws IOException {
            StringBuilder buffer = new StringBuilder(
                    "<tr><td colspan=\"4\" style=\"border-width:0px;font-size:"
                            + SECTION_FONT_SIZE
                            + ";padding:20pt 0pt 10pt 0pt;font-family:arial,verdana,helvetica;background-color:white\">");
            boolean next = false;
            for (String protocol : protocols) {
                if (next) {
                    buffer.append(", &nbsp;");
                } else {
                    next = true;
                }
                buffer.append("<span id=\"").append(makeLink(protocol))
                        .append("\">").append(main_object ? "" : "<i>")
                        .append(protocol)
                        .append(main_object ? "</span>" : "</i></span>");
            }
            buffer.append("</td></tr>\n<tr><th>Property</th><th>Type</th><th>"
                    + REQUIRED_COLUMN + "</th><th>Comment</th></tr>");
            int i = 0;
            int supress = 0;
            for (Row row : rows) {
                if (row.header != null) {
                    buffer.append("<tr><th colspan=\"4\" id=\"")
                          .append(makeLink(row.header))
                          .append("\">")
                          .append(row.header)
                          .append("</th></tr>");
                }
                if (row.set_group) {
                    supress = row.depth;
                }
                i++;
                buffer.append("<tr>");
                if (row.columns.size() != 4) {
                    throw new IOException("Wrong number of colums for row: "
                            + i);
                }
                int q = 0;
                for (Row.Column column : row.columns) {
                    boolean output = true;
                    boolean standard = true;
                    q++;
                    if (q == 3) {
                        if (supress != 0) {
                            if (row.set_group) {
                                standard = false;
                                buffer.append(
                                        "<td style=\"text-align:center\" rowspan=\"")
                                        .append(supress).append("\">");
                            } else {
                                output = false;
                            }
                            supress--;
                        }
                    }
                    if (output == standard) {
                        buffer.append(q == 1 ? "<td style=\"white-space:nowrap\" id=\""
                                + row.property_link + "\">"
                                : (q < 4 ? "<td style=\"text-align:center\">"
                                        : "<td>"));
                    }
                    if (output) {
                        buffer.append(column.column).append("</td>");
                    }
                }
                buffer.append("</tr>");
            }
            if (notes != null) {
                buffer.append(
                        "<tr><td colspan=\"4\" style=\"background-color:white;border-width:0px;padding:10pt 0pt 0pt 0pt\">")
                        .append(notes).append("</td></tr>");
            }
            return buffer.toString();
        }

        @Override
        public Row newRow() {
            return new Row();
        }

        void setNotes(String notes) throws IOException {
            if (this.notes == null) {
                this.notes = notes;
            } else {
                throw new IOException("Notes already defined:" + protocols[0]);
            }
        }
    }

    Vector<ProtocolObject> protocol_objects = new Vector<ProtocolObject> ();
    
    Vector<Content> division_objects = new Vector<Content> ();
    
    StringBuilder html;
    int local_toc_sec;

    public String getHTML () throws IOException {
        LinkedHashMap<String,TOCEntry> save = toc;
        toc = new LinkedHashMap<String,TOCEntry>();
        for (String toc_entry : save.keySet()) {
            toc.put(toc_entry, save.get(toc_entry));
            if (toc_entry.equals(protocol_table_header)) {
                for (ProtocolObject protocol_object : protocol_objects) {
                    for (String prot : protocol_object.protocols) {
                        TOCEntry te = new TOCEntry();
                        te.link = makeLink(prot);
                        te.indented = true;
                        te.italic = !protocol_object.main_object;
                        toc.put(prot, te);
                    }
                }
            }
        }
        
        html = new StringBuilder(
            "<!DOCTYPE html>" +
            "<html><head><title>")
         .append(subsystem_name)
         .append("</title>" +
                 "<meta http-equiv=Content-Type content=\"text/html; charset=utf-8\">" +
                 "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        if (favIcon != null) {
            html.append("<link rel=\"icon\" href=\"")
                .append(favIcon)
                .append("\" sizes=\"192x192\">");
        }
        html.append("<style type=\"text/css\">\n" +
                 ".tftable {border-collapse: collapse}\n" +
                 ".tftable th {font-size:10pt;background: linear-gradient(to bottom, #eaeaea 14%,#fcfcfc 52%,#e5e5e5 89%);border-width:1px;padding:4pt 10pt 4pt 10pt;border-style:solid;border-color: #a9a9a9;text-align:center;font-family:arial,verdana,helvetica}\n" +
                 ".tftable tr {background-color:#FFFFE0}\n" +
                 ".tftable td {font-size:10pt;border-width:1px;padding:4pt 8pt 4pt 8pt;border-style:solid;border-color:#a9a9a9;font-family:arial,verdana,helvetica}\n" +
                 "div {font-size:10pt;padding:10pt 0pt 0pt 0pt;font-family:arial,verdana,helvetica}\n" +
                 "a {color:blue;font-family:verdana,helvetica;text-decoration:none}\n");
        html.append(external_styles)
         .append("</style></head><body style=\"margin:15pt\">" +
                 "<div style=\"cursor:pointer;padding:2pt 0 0 0;position:absolute;top:15pt;left:15pt;z-index:5;visibility:visible;width:100pt;" +
                 "height:47pt;border-width:1px;border-style:solid;border-color:black;box-shadow:3pt 3pt 3pt #D0D0D0\"" +
                 " onclick=\"document.location.href='http://webpki.org'\" title=\"Home of WebPKI.org\">")
          .append(new String(ArrayUtil.getByteArrayFromInputStream (getClass().getResourceAsStream ("webpki-logo.svg")),"UTF-8"))
          .append("</div>");
        for (Content division_object : division_objects) {
            html.append(division_object.getHTML ());
        }
        return html.append("</body></html>").toString();
    }
    
    public void writeHTML() throws IOException {
        ArrayUtil.writeFile(file_name, getHTML().getBytes("UTF-8"));
    }

    public ProtocolObject addProtocolTable(String protocol) {
        return new ProtocolObject(new String[] { protocol }, true);
    }

    public ProtocolObject addSubItemTable(String sub_item) {
        return new ProtocolObject(new String[] { sub_item }, false);
    }

    public ProtocolObject addSubItemTable(String[] sub_items) {
        return new ProtocolObject(sub_items, false);
    }

    public StringBuilder addParagraphObject() throws IOException {
        return addParagraphObject(null);
    }

    public StringBuilder addParagraphObject(String header) throws IOException {
        return addParagraphObject(header, true);
    }

    public StringBuilder addParagraphSubObject(String header) throws IOException {
        return addParagraphObject(header, false);
    }

    StringBuilder addParagraphObject(String header, boolean top_level) throws IOException {
        Paragraph p = new Paragraph();
        StringBuilder buffer = new StringBuilder("<div style=\"width:" + PAGE_WIDTH + "\">");
        if (header != null) {
            if (top_level) {
                curr_toc_seq++;
                local_toc_sec = 0;
            } else {
                local_toc_sec++;
            }
            TOCEntry te = new TOCEntry();
            te.link = makeLink(header);
            te.sequence = curr_toc_seq;
            te.sub_seq = local_toc_sec;
            te.appendix = appendix_mode;
            te.indented = !top_level;
            te.prefix_on = true;
            if (toc.put(header, te) != null) {
                throw new IOException("Duplicate TOC: " + header);
            }
            buffer.append("<div style=\"padding:10pt 0pt 10pt 0pt\" id=\"")
             .append(te.link)
             .append("\"><span style=\"font-size:" + (top_level ? CHAPTER_FONT_SIZE : SECTION_FONT_SIZE) + "\">")
             .append(te.getPrefix ())
             .append(header)
             .append("</span></div>");
        }
        return p.local_html = buffer;
    }

    public void niceSquare (String html_in_div, int bottom_margin) throws IOException {
        addParagraphObject(null).append("<table style=\"border-width:1px;padding:4pt 10pt 4pt 10pt;border-style:solid;border-color: #808080;margin-left:auto;margin-right:auto;box-shadow:3pt 3pt 3pt #D0D0D0;margin-bottom:")
                                 .append(bottom_margin)
                                 .append("pt\"><tr><td>")
                                 .append(html_in_div)
                                 .append("</td></tr></table>");
    }

    public static String makeLink (String header) throws IOException {
        StringBuilder buffer = new StringBuilder();
        for (char c : header.toCharArray()) {
            if (URLEncoder.encode(new String(new char[]{c}), "UTF-8").charAt(0) != c) {
                c = '_';
            }
            buffer.append(c);
        }
        return buffer.toString();
    }

    public void addDataTypesDescription (String intro) throws IOException {
        addParagraphObject("Notation").append(intro);
        new DataTypeDescription();
        addParagraphObject("Data Types").append("The table below shows how the data types used by this specification are mapped into native JSON types:");
        new DataTypesTable ();
    }

    public static String enumerateStandardAlgorithms (CryptoAlgorithms[] algorithms, boolean symmetric, boolean filter) throws IOException {
        StringBuilder buffer = new StringBuilder("<ul>");
        for (CryptoAlgorithms algorithm : algorithms) {
            if (algorithm.isDeprecated()) {
                continue;
            }
            if (filter && algorithm instanceof KeyAlgorithms && !((KeyAlgorithms)algorithm).isECKey()) {
                continue;
            }
            if (symmetric ^ algorithm.isSymmetric()) {
                continue;
            }
            if (algorithm instanceof AsymSignatureAlgorithms && ((AsymSignatureAlgorithms)algorithm).getDigestAlgorithm() == null && filter) {
                continue;
            }
            buffer.append("<li><code>").append(algorithm.getAlgorithmId(AlgorithmPreferences.SKS)).append("</code></li>");
        }
        return buffer.append("</ul>").toString();
    }

    public static String enumerateJOSEAlgorithms(CryptoAlgorithms[] algorithms) throws IOException {
        StringBuilder buffer = new StringBuilder("<ul>");
        for (CryptoAlgorithms algorithm : algorithms) {
            String joseName = algorithm.getAlgorithmId(AlgorithmPreferences.JOSE_ACCEPT_PREFER);
            if (!joseName.contains (":")) {
                buffer.append("<li><code>")
                      .append(joseName)
                      .append("</code></li>");
            }
        }
        return buffer.append("</ul>").toString();
    }

    static String enumerateAttributes(String[] list, boolean andFlag) {
        StringBuilder s = new StringBuilder();
        int i = 0;
        for (String attribute : list) {
            if (i == list.length - 1) {
                s.append(andFlag ? " and " : " or ");
            } else if (i++ > 0) {
                s.append(", ");
            }
            s.append("<code>&quot;")
             .append(attribute)
             .append("&quot;</code>");
        }
        return s.toString();
    }
    
    static String referToTestVector(String name) throws IOException {
        return "Also see the <a href=\"#" + makeLink(name) + "\">" + name + "</a> test vector.";
    }

    String protocol_table_header;
    
    public StringBuilder addProtocolTableEntry(String header) throws IOException {
        StringBuilder buffer = addParagraphObject(protocol_table_header = header);
        new ProtocolTable ();
        return buffer;
    }

    public void addReferenceTable () throws IOException {
        addParagraphObject("References");
        new References ();
    }

    public void renderProtocolSteps (@SuppressWarnings("rawtypes") Class parent,
                                    StringBuilder buffer, ProtocolStep[] protocol_steps) throws IOException {
        JSONObjectWriter.htmlIndent = 2;
        buffer.append("<table class=\"tftable\" style=\"margin-top:10pt\">");
        boolean next = false;
        for (ProtocolStep protocol_step : protocol_steps) {
            JSONObjectReader or = JSONParser.parse(ArrayUtil.getByteArrayFromInputStream (parent.getResourceAsStream (protocol_step.json_file)));
            if (next) {
                buffer.append("<tr><td style=\"border-width:0px;height:10px;background-color:white\"></td></tr>");
            } else {
                next = true;
            }
            buffer.append("<tr><th id=\"Sample.")
                  .append(or.getString(JSONDecoderCache.QUALIFIER_JSON))
                  .append("\">")
                  .append(or.getString(JSONDecoderCache.QUALIFIER_JSON))
                  .append("</th></tr><tr><td><code>")
                  .append(or.serializeToString(JSONOutputFormats.PRETTY_HTML))
                  .append("</code></td></tr>");
            if (protocol_step.optional_table_comment_HTML != null) {
                buffer.append("<tr><td style=\"background-color:white;border-width:0px;padding:10pt 0pt 10pt 0pt\">")
                      .append(protocol_step.optional_table_comment_HTML)
                      .append("</td></tr>");
                next = false;
            }
        }
        buffer.append("</table>");
    }

    public void sampleRun(@SuppressWarnings("rawtypes") Class parent,
                          String header, ProtocolStep[] protocol_steps) throws IOException {
        StringBuilder buffer = addParagraphObject("Sample Run").append(header);
        renderProtocolSteps(parent, buffer, protocol_steps);
    }
    
    static String makeName(String name) {
        StringBuilder s = new StringBuilder();
        for (char c : name.toCharArray()) {
            if (c == ' ') {
                s.append("&nbsp;");
            } else {
                s.append(c);
            }
        }
        return s.toString();
    }

    public String globalLinkRef(String name) throws IOException {
        return "<a href=\"#" + makeLink(name) + "\">" + makeName(name) +"</a>"; 
    }

    public String globalLinkRef(String parent, String name) throws IOException {
        return "<a href=\"#" + makeLink(parent) + "." + makeLink(name) + "\">" + makeName(name) +"</a>"; 
    }

    String brackit(String string) {
        return "[" + string + "]";
    }

    public void addReferenceEntry(String reference, String html_description) throws IOException  {
        Reference r = new Reference();
        if (reference.matches("RFC[1-9][0-9]+")) {
            html_description += " " + externalWebReference("https://tools.ietf.org/html/" + reference.toLowerCase());
        }
        r.html_description = html_description;
        Reference old = references.put(reference, r);
        if (old != null && !old.html_description.equals(html_description)) {
            throw new IOException("Reference ambigiously defined: " + reference);
        }
    }
    
    public String createReference(String reference) throws IOException {
        Reference r = references.get (reference);
        if (r == null) {
            throw new IOException("No such reference: " + reference);
        }
        r.referenced = true;
        return "<a href=\"#Reference." + reference + "\">" + brackit(reference) +"</a>"; 
    }

    StringBuilder doc_history;
    
    public void addDocumentHistoryLine (String date, String version, String comment) throws IOException {
        if (doc_history == null) {
            doc_history = addParagraphObject("Document History")
                       .append("<table class=\"tftable\"><tr><th>Date</th><th>Ver</th><th>Comment</th></tr></table>");
        }
        doc_history.insert (doc_history.lastIndexOf ("</table>"), "<tr><td>" + date + "</td><td style=\"text-align:center\">" + version + "</td><td>" + comment + "</td></tr>");
    }
    
    public void AddPublicKeyDefinitions() throws IOException {
        addSubItemTable(JSONCryptoHelper.PUBLIC_KEY_JSON)
        .newRow()
          .newColumn()
            .addProperty(JSONCryptoHelper.KTY_JSON)
            .addSymbolicValue("Key Type")
          .newColumn()
            .setType(Types.WEBPKI_DATA_TYPES.STRING)
          .newColumn()
          .newColumn()
            .addString("Key type indicator.  Currently the following types are recognized:<ul>" +
                    "<li>" + JSONBaseHTML.codeVer(JSONCryptoHelper.EC_PUBLIC_KEY, 6) + "See: ")
                    .addLink (JCS_PUBLIC_KEY_EC)
            .addString("</li><li>" + 
                     JSONBaseHTML.codeVer(JSONCryptoHelper.RSA_PUBLIC_KEY, 6) + "See: ")
            .addLink (JCS_PUBLIC_KEY_RSA)
            .addString("</li></ul>")
       .newRow(JCS_PUBLIC_KEY_EC)
          .newColumn()
            .addProperty(JSONCryptoHelper.CRV_JSON)
            .addSymbolicValue("Curve Name")
          .newColumn()
            .setType(Types.WEBPKI_DATA_TYPES.STRING)
          .newColumn()
          .newColumn()
            .addString("EC curve name. The currently recognized EC curves include:")
            .addString(enumerateJOSEAlgorithms(KeyAlgorithms.values()))
            .addString("Note: If <i>proprietary</i> curve names are added, they <b>must</b> be expressed as URIs.")
      .newRow()
        .newColumn()
          .addProperty(JSONCryptoHelper.X_JSON)
          .addSymbolicValue("Coordinate")
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY)
        .newColumn()
        .newColumn()
          .addString("EC curve point X. The length of this field <b>must</b> " +
                      "be the full size of a coordinate for the curve specified in the <code>" + 
                      JSONCryptoHelper.CRV_JSON + "</code> parameter.  For example, " +
                      "if the value of <code>" + JSONCryptoHelper.CRV_JSON + "</code> is <code>" +
                      KeyAlgorithms.NIST_P_521.getAlgorithmId (AlgorithmPreferences.JOSE) +
                      "</code>, the <i>decoded</i> argument <b>must</b> be 66 bytes.")
      .newRow()
        .newColumn()
          .addProperty(JSONCryptoHelper.Y_JSON)
          .addSymbolicValue("Coordinate")
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY)
        .newColumn()
        .newColumn()
          .addString("EC curve point Y. The length of this field <b>must</b> " +
                      "be the full size of a coordinate for the curve specified in the <code>" + 
                      JSONCryptoHelper.CRV_JSON + "</code> parameter.  For example, " +
                      "if the value of <code>" + JSONCryptoHelper.CRV_JSON + "</code> is <code>" +
                      KeyAlgorithms.NIST_P_256.getAlgorithmId (AlgorithmPreferences.JOSE) +
                      "</code>, the <i>decoded</i> argument <b>must</b> be 32 bytes.")
      .newRow(JCS_PUBLIC_KEY_RSA)
        .newColumn()
          .addProperty(JSONCryptoHelper.N_JSON)
          .addSymbolicValue("Modulus")
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.CRYPTO)
        .newColumn()
        .newColumn()
          .addString("RSA modulus. Also see the ")
          .addDataTypeLink (Types.WEBPKI_DATA_TYPES.CRYPTO)
          .addString(" data type.")
      .newRow()
        .newColumn()
          .addProperty(JSONCryptoHelper.E_JSON)
          .addSymbolicValue("Exponent")
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.CRYPTO)
        .newColumn()
        .newColumn()
          .addString("RSA exponent. Also see the ")
          .addDataTypeLink (Types.WEBPKI_DATA_TYPES.CRYPTO)
          .addString(" data type.")
        .setNotes("This object represents a <i>subset</i> of JWK " + createReference(REF_JWK) +".");
        
    }

    public void addJSONSignatureDefinitions () throws IOException {
// TODO
        addSubItemTable(JSONObjectWriter.SIGNATURE_DEFAULT_LABEL_JSON)
          .newRow()
            .newColumn()
              .addProperty(JSONCryptoHelper.ALGORITHM_JSON)
              .addSymbolicValue("Algorithm")
            .newColumn()
              .setType(Types.WEBPKI_DATA_TYPES.STRING)
            .newColumn()
            .newColumn()
              .addString("Signature algorithm. The currently recognized JWA ")
              .addString(createReference(REF_JWA))
              .addString(" asymmetric key algorithms include:")
              .addString(enumerateJOSEAlgorithms(AsymSignatureAlgorithms.values()))
              .addString("The currently recognized JWA ")
              .addString(createReference(REF_JWA))
              .addString(" symmetric key algorithms include:")
              .addString(enumerateJOSEAlgorithms(MACAlgorithms.values()))
              .addString("Note: If <i>proprietary</i> signature algorithms are added, they <b>must</b> be expressed as URIs.")
          .newRow()
            .newColumn()
              .addProperty(JSONCryptoHelper.KEY_ID_JSON)
              .addSymbolicValue("Identifier")
            .newColumn()
              .setType(Types.WEBPKI_DATA_TYPES.STRING)
            .newColumn()
              .setChoice (false, 1)
            .newColumn()
              .addString("<i>Optional.</i> Application specific string identifying the signature key.")
          .newRow()
            .newColumn()
              .addProperty(JSONCryptoHelper.PUBLIC_KEY_JSON)
              .addLink (JSONCryptoHelper.PUBLIC_KEY_JSON)
            .newColumn()
              .setType(Types.WEBPKI_DATA_TYPES.OBJECT)
            .newColumn()
              .setChoice (false, 4)
            .newColumn()
              .addString("<i>Optional.</i> Public key object.")
          .newRow()
        .newColumn()
          .addProperty(JSONCryptoHelper.CERTIFICATE_PATH)
          .addArrayList(Types.CERTIFICATE_PATH, 1)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY2)
        .newColumn()
        .newColumn()
          .addString("<i>Optional.</i> Sorted array of X.509 ")
          .addString(createReference(REF_X509))
          .addString(" certificates, where the <i>first</i> element <b>must</b> contain the <i style=\"white-space:nowrap\">signature certificate</i>. " +
                      "The certificate path <b>must</b> be <i>contiguous</i> but is not required to be complete.")
             .newRow()
                .newColumn()
                  .addProperty(JSONCryptoHelper.EXTENSIONS_JSON)
                  .addArrayList(Types.PROPERTY_LIST, 1)
                .newColumn()
                  .setType(Types.WEBPKI_DATA_TYPES.STRING)
                .newColumn()
                  .setChoice (false, 1)
                .newColumn()
                  .addString("<i>Optional.</i> Array holding the names of one or more application specific extension properties " +
                  "also featured within the signature object." +
                  Types.LINE_SEPARATOR +
                  "Extension names <b>must not</b> be <i>duplicated</i> or use any of the JCS <i>reserved words</i> " +
                  enumerateAttributes(JSONCryptoHelper.jcsReservedWords.toArray(new String[0]), false) + ". " +
                  Types.LINE_SEPARATOR +
                  "Extensions intended for public consumption are <i>preferably</i> expressed as URIs " +
                  "(unless registered with IANA), " +
                  "while private schemes are free using any valid property name." + Types.LINE_SEPARATOR +
                  "A conforming JCS implementation <b>must</b> <i>reject</i> signatures listing properties " +
                  "that are not found as well as empty <code>&quot;" +
                  JSONCryptoHelper.EXTENSIONS_JSON + "&quot;</code> objects. " +
                  "Verifiers are <i>recommended</i> introducing additional constraints like only accepting predefined extensions." +
                  Types.LINE_SEPARATOR +
                  "Also see <a href=\"#" + EXTENSION_EXAMPLE + "\">test&nbsp;vector</a>.")
             .newRow()
                .newColumn()
                  .addProperty(JSONCryptoHelper.EXCLUDE_JSON)
                  .addArrayList(Types.PROPERTY_LIST, 1)
                .newColumn()
                  .setType(Types.WEBPKI_DATA_TYPES.STRING)
                .newColumn()
                  .setChoice (false, 1)
                .newColumn()
                  .addString("<i>Optional.</i> Array holding the names of one or more properties " +
                  "featured on the same level as the <code>&quot;signature" + 
                  "&quot;</code> property, that <b>must</b> be <i>excluded</i> from the signature process." +
                  Types.LINE_SEPARATOR +
                  "Note that the <code>&quot;" + JSONCryptoHelper.EXCLUDE_JSON + "&quot;</code> property itself, <b>must</b> also " +
                  "be excluded from the signature process." + 
                  Types.LINE_SEPARATOR +
                  "Property names that are to be excluded from the signature process " +
                  "<b>must not</b> be <i>duplicated</i> or override the signature object label. " +
                  Types.LINE_SEPARATOR +
                  "A conforming JCS implementation <b>must</b> <i>reject</i> signatures containing listed properties " +
                  "that are not found as well as empty <code>&quot;" +
                  JSONCryptoHelper.EXCLUDE_JSON + "&quot;</code> objects. " +
                  "Verifiers are <i>recommended</i> introducing additional constraints like only accepting predefined properties." +
                  Types.LINE_SEPARATOR +
                  "Also see <a href=\"#" + EXCLUSION_EXAMPLE + "\">test&nbsp;vector</a>.")
          .newRow()
            .newColumn()
              .addProperty(JSONCryptoHelper.VALUE_JSON)
              .addSymbolicValue("Signature")
            .newColumn()
              .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY)
            .newColumn()
            .newColumn()
              .addString("The signature data." +
              " Note that the <i>binary</i> representation <b>must</b> follow the JWA " + 
                      createReference(REF_JWA) + " specifications.")
              .setNotes ("Note that asymmetric key signatures are <i>not required</i> providing an associated " +
                  enumerateAttributes(new String[]{JSONCryptoHelper.PUBLIC_KEY_JSON,
                                                   JSONCryptoHelper.CERTIFICATE_PATH}, false) + 
                   " property since the key may be given by the context or through the <code>&quot;" + 
                   JSONCryptoHelper.KEY_ID_JSON + "&quot;</code> property.");

        AddPublicKeyDefinitions();
    }

    public void addTOC() {
        new TOC();
    }

    public void setAppendixMode() {
        curr_toc_seq = 0;
        appendix_mode = true;
    }

    private boolean has_already_out_dialog_styles;

    private String favIcon;
    
    public String createDialog(String header, String content) {
        if (!has_already_out_dialog_styles) {
            has_already_out_dialog_styles = true;
            addGlobalStyle(".dlgbtn {border-radius:3pt;border-color:grey;border-style:solid;border-width:2pt;background-color:lightgrey;padding:2pt 4pt 2pt 4pt;margin-bottom:2pt;display:inline-block}\n" +
                           ".dlgtext {border-color:black;border-style:solid;border-width:1pt;padding:2pt 4pt 2pt 4pt;font-weight:bold;font-family:\"Courier New\",courier,helvetica}\n" +
                           ".dlgtbl {padding:0px;margin-top:10pt;margin-bottom:10pt;margin-left:auto;margin-right:auto;border-color:grey;border-style:solid;border-width:1pt;border-spacing:0px;box-shadow:3pt 3pt 3pt #D0D0D0}\n" +
                           ".dlgtbl td {background-color:white;border-width:0px}\n");
        }
        return 
          "<table class=\"dlgtbl\"><tr><td colspan=\"2\" style=\"text-align:center;font-size:14pt;font-family:arial,verdana,helvetica;background-color:lightblue;border-width:0pt 0pt 1pt 0pt\">" +
          header + "</td></tr>" + content +
          "<tr><td><div class=\"dlgbtn\">Cancel</div></td><td style=\"text-align:right\"><div class=\"dlgbtn\">&nbsp;&nbsp;OK&nbsp;&nbsp;</div></td></tr>" +
          "</table>";      
    }

    public String addInvocationText(String protocol_name, Class<? extends JSONDecoder> invocation_class)
            throws IOException {
        JSONDecoder decoder = null;
        try {
            decoder = invocation_class.newInstance();
        } catch (InstantiationException e) {
            throw new IOException(e);
        } catch (IllegalAccessException e) {
            throw new IOException(e);
        }
        return
          "Since the interface between the Web and native applications is not (yet) standardized, the " +
          "invocation of " + protocol_name + " relies on browser and platform specific solutions. " +
          "For Android, &quot;Intents&quot; are currently utilized for handing over an invocation URL " +
          "(including possible session cookies), to a local " + protocol_name + " &quot;App&quot;.";
    }

    public void setFavIcon(String favIcon) {
        this.favIcon = favIcon;
    }
}
