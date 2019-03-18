package com.example.es6numbers;

import java.io.FileOutputStream;
import java.util.LinkedHashMap;
import java.util.Vector;

public class PropertyTest {

    static final int MAX_PROP_LEN = 20;
    static final int MIN_PROP_LEN = 2;
    
    final static char[] PROPERTY_CHARS = {
        'A','B','C','D','E','F','G','H',
        'I','J','K','L','M','N','O','P',
        'Q','R','S','T','U','V','W','X',
        'Y','Z','a','b','c','d','e','f',
        'g','h','i','j','k','l','m','n',
        'o','p','q','r','s','t','u','v',
        'w','x','y','z','0','1','2','3',
        '4','5','6','7','8','9','_','@',
        '$'
    };
    
    static FileOutputStream fos;
    
    static StringBuilder testCalls = new StringBuilder();
    
    static StringBuilder testData = new StringBuilder();
    
    static void write(byte[] utf8) throws Exception {
        fos.write(utf8);
    }

    static void write(String utf8) throws Exception {
        write(utf8.getBytes("UTF-8"));
    }
    
    static void test(int numberOfProperties) throws Exception {
        write("<tr><td>" + numberOfProperties + "</td><td id=\"n" + numberOfProperties + "\">Not tested yet</td></tr>");
        LinkedHashMap<String,String> values = new LinkedHashMap<String,String>();
        Vector<String> deletes = new Vector<String> ();
        int q = 1;
        while (q <= numberOfProperties) {
            String value = String.valueOf(q);
            if (q % 2 == 0) {
                value = "[" + value + "]";
            } else if (q % 3 == 0) {
                value = "{\"test\":" + value + "}";
            }
            String property = getProperty();
            if (values.put(property, value) == null) {
                if (q == 1 || q == numberOfProperties - 1 || q % 10 == 0) {
                    deletes.add(property);
                }
                q++;
            }
        }
        testCalls.append("  test('n" + 
                numberOfProperties + "', string" +
                numberOfProperties + ", inline" +
                numberOfProperties + ", object" +
                numberOfProperties + "(),[");
        boolean next = false;
        for (String property : deletes) {
            if (next) {
                testCalls.append(',');
            }
            next = true;
            testCalls.append('\'').append(property).append('\'');
        }
        testCalls.append("]);\n");
        testData.append("\n// In-line declarated object\nvar inline" + numberOfProperties + " = {\n");
        next = false;
        for (String property : values.keySet()) {
            if (next) {
                testData.append(",\n");
            }
            next = true;
            String field = property;
            if (field.contains("@")) {
                field = "\"" + field + "\"";
            }
            testData.append("  " + field + ": " + values.get(property));
        }
        testData.append("\n};\n\n// JSON string\nvar string" + numberOfProperties + " = '{");
        next = false;
        for (String property : values.keySet()) {
            if (next) {
                testData.append(",");
            }
            next = true;
            testData.append("\"" + property + "\":" + values.get(property));
        }
        testData.append("}';\n");
        testData.append("\n// Dynamically created object\nfunction object" + numberOfProperties + "() {\n" +
                        "  var o = {};\n");
        for (String property : values.keySet()) {
            String field = property;
            if (field.contains("@")) {
                field = "[\"" + field + "\"]";
            } else {
                field = "." + field;
            }
            testData.append("  o" + field + " = " + values.get(property) + ";\n");
        }
        testData.append("  return o;\n};\n");
    }

    static String getProperty() {
        int length  = (int)((Math.random() * (MAX_PROP_LEN - MIN_PROP_LEN + 1)) + MIN_PROP_LEN);
        boolean alpha = true;
        StringBuilder s = new StringBuilder();
        while (length-- > 0) {
            s.append(getChar(alpha));
            alpha = false;
        }
        return s.toString();
    }

    static char getChar(boolean alpha) {
        while (true) {
            char c = PROPERTY_CHARS[(int)(Math.random() * PROPERTY_CHARS.length)];
            if (alpha && c >= '0' && c <= '9') {
                continue;
            }
            return c;
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.out.println("\nUsage: " + PropertyTest.class.getCanonicalName()
                    + "browsertestpage");
            System.exit(-3);
        }
        fos = new FileOutputStream(args[0]);
        // Header
        write("<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>ES6 - Property Ordering</title>"
                + "<style type=\"text/css\">"
                + "body {font-family:verdana;font-size:10pt}"
                + "th {background:lightgrey;font-family:verdana;font-size:10pt;font-weight:normal;padding:4pt}"
                + "td {font-family:verdana;font-size:10pt;font-weight:normal;padding:2pt}"
                + "</style></head><body onload=\"runTests()\"><h3>ES6 - JSON Property Order Tester</h3>"
                + "This program verfies that the &quot;predictable property order&quot; introduced in ES6,<br>"
                + "actually works including for JSON parsing and serialization.<br>&nbsp;"
                + "<table border=\"1\" cellspacing=\"0\"><tr><th>Cycles</th><th>Result</th></tr>");
        test(1);
        test(5);
        test(10);
        test(100);
        test(1000);
        test(10000);
        write("</table><script type=\"text/javascript\">\n\n\"use strict\";\n");
        write(testData.toString());
        write("\nfunction test(id, stringForm, inlineDeclaration, dynamicCreated, deleteProperties) {\n" +
              "  var result = 'passed';\n" +
              "  if (stringForm != JSON.stringify(inlineDeclaration)) {\n" +
              "    result = 'fail-1';\n" +
              "  } else if (stringForm != JSON.stringify(JSON.parse(stringForm))) {\n" +
              "    result = 'fail-2';\n" +
              "  } else if (stringForm != JSON.stringify(dynamicCreated)) {\n" +
              "    result = 'fail-3';\n" +
              "  } else {\n" +
              "    for (var q = 0; q < deleteProperties.length; q++) {\n" +
              "      var cloneString = JSON.stringify(JSON.parse(stringForm));\n" +
              "      var cloneInline = Object.assign({},inlineDeclaration);\n" +
              "      delete cloneInline[deleteProperties[q]];\n" +
              "      var i = cloneString.indexOf('\"' + deleteProperties[q] + '\"');\n" +
              "      var prop = cloneString.substring(i);\n" +
              "      var j = prop.indexOf(':') + 1;\n" +
              "      if (prop.charAt(j) == '{') {\n" +
              "        j = prop.indexOf('}') + 1;\n" +
              "      }\n" +
              "      while(true) {\n" +
              "        if (prop.charAt(j) == '}') {\n" +
              "          if (cloneString.charAt(i - 1) == ',') {\n" +
              "            i--; j ++;\n" +
              "          }\n" +
              "          break;\n" +
              "        } else if (prop.charAt(j) == ',') {\n" +
              "          j++;\n" +
              "          break;\n" +
              "        }\n" +
              "        j++;\n" +
              "      }\n" +
              "      cloneString = cloneString.substring(0,i) + cloneString.substring(i + j);\n" +
              "      if (cloneString != JSON.stringify(cloneInline)) {\n" +
              "        console.debug(cloneString);\n" +
              "        console.debug(JSON.stringify(cloneInline));\n" +
              "        result = 'fail-4=' + deleteProperties[q];\n" +
              "        break;\n" +
              "      }\n" +
              "    }\n" +
              "  }\n" +
              "  document.getElementById(id).innerHTML = result;\n" +
              "}\n" +
              "\nfunction runTests() {\n");
        write(testCalls.toString());
        write("}\n</script>\n");
        write("</body></html>\n");
        fos.close();
    }
}
