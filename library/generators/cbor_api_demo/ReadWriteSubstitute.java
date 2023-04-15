package cbor_api_demo;

import java.io.IOException;

import org.webpki.util.ArrayUtil;
import org.webpki.util.UTF8;

public class ReadWriteSubstitute {

    static String readString(String fileName) throws IOException {
        return new String(ArrayUtil.readFile(fileName), "utf-8");
    }

    static void writeString(String fileName, String data) throws IOException {
        ArrayUtil.writeFile(fileName, UTF8.encode(data));
        return;
    }
    
    static void replace(String fileName, String holder, String data) throws IOException {
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
