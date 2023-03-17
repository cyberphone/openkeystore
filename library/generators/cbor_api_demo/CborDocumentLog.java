package cbor_api_demo;

import java.io.IOException;

import org.webpki.cbor.CBORObject;

import org.webpki.util.HexaDecimal;

public class CborDocumentLog {
    
    CborDocumentLog(String fileName, String holder, byte[] binaryData) throws IOException {
        ReadWriteSubstitute.replace(fileName, 
                                    holder,
                                    HexaDecimal.encode(binaryData));
    }

    CborDocumentLog(String fileName, String holder, CBORObject cbor) throws IOException {
        ReadWriteSubstitute.replace(fileName, 
                                    holder,
                                    ReadWriteSubstitute.htmlIze(cbor.toString()));
    }

    CborDocumentLog(String fileName, String sourceCodeFile, String holder) throws IOException {
        String source = ReadWriteSubstitute.readString(sourceCodeFile)
                .replaceAll("new CborDocumentLog.*\\n", "");
        ReadWriteSubstitute.replace(fileName, 
                holder,
                ReadWriteSubstitute.htmlIze(source));
    }
    
}
