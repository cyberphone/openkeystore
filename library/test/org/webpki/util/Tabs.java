package org.webpki.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

public class Tabs {
    
    static void traverse(File fileOrDirectory) throws IOException {
        if (fileOrDirectory.isDirectory()) {
            String[] files = fileOrDirectory.list();
            for (String listedFile : files) {
                traverse(new File(fileOrDirectory, listedFile));
            }
            return;
        }
        String path = fileOrDirectory.getPath();
        if (!path.endsWith(".java")) {
            return;
        }
        StringBuilder data = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(fileOrDirectory))) {
            String line;
            int i = 0;
            int indentations = 0;
            boolean continuedLine = false;
            while ((line = br.readLine()) != null) {
                line = line.stripTrailing();
                if (line.stripLeading().length() == 0) {
                    line = "";
                }
                int pos = 0;
                int spaces = 0;
                if (continuedLine) {
                    for (int q = 0; q < indentations; q++) {
                        pos += 2;
                    }
                    if (pos > 0) pos--;
                    spaces = -1;
                } else {
                    indentations = 0;
                }
                while (pos < line.length()) {
                    char c = line.charAt(pos++);
                    if (spaces >= 0 && c == ' ') {
                        if (++spaces == 4) {
                            indentations++;
                            data.append("  ");
                            spaces = 0;
                        }
                    } else {
                        while (spaces-- >= 0) {
                            data.append(' ');
                        }
                        data.append(c);
                     }
                }
                data.append('\n');
                i++;
                continuedLine = line.length() > 0 && 
                        (line.charAt(line.length() - 1) == ',' ||
                         line.charAt(line.length() - 1) == ',' ||
                         line.charAt(line.length() - 1) == '+');
            }
            System.out.println("File=" + path + " lines=" + i);
            ArrayUtil.writeFile(path, data.toString().getBytes("utf-8"));
        }
    }

    public static void main(String[] args) {
        try {
            traverse(new File(args[0]));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
