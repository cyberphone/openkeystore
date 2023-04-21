package cbor_api_demo;

import org.webpki.util.IO;
import org.webpki.util.UTF8;

public class ReadWriteSubstitute {

    static String readString(String fileName) {
        return UTF8.decode(IO.readFile(fileName));
    }

    static void writeString(String fileName, String data) {
        IO.writeFile(fileName, UTF8.encode(data));
        return;
    }
    
    static void replace(String fileName, String holder, String data) {
        String fileData = readString(fileName);
        writeString(fileName, fileData.replace(holder, data));
    }
    
    static String htmlIze(String string) {
        return string.replace("&", "&amp;")
                     .replace("<", "&lt;")
                     .replace(">", "&gt;")
                     .replace(" ", "&nbsp;")
                     .replace("\n", "<br>");
    }
}
