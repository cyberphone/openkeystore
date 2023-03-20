package cbor_api_demo;

import java.io.IOException;

import org.webpki.cbor.CBORArray;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORTypes;
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
        String source = ReadWriteSubstitute.readString(sourceCodeFile);
        source = source.substring(0, source.indexOf("//@begin@")) +
                source.substring(source.indexOf("//@end@\n") + 8);
        ReadWriteSubstitute.replace(fileName, 
                holder,
                ReadWriteSubstitute.htmlIze(source));
    }

    CborDocumentLog() {
        // TODO Auto-generated constructor stub
    }
    
    void traverse(CBORObject refData, CBORObject newData) throws IOException {
        switch (refData.getType()) {
            case MAP:
                CBORMap refMap = refData.getMap();
                CBORMap newMap = newData.getMap();
                for (CBORObject key : refMap.getKeys()) {
                    CBORObject refValue = refMap.getObject(key);
                    CBORObject newValue = newMap.getObject(key);
                    if (refValue.getType() == CBORTypes.BYTE_STRING) {
                        byte[] refBlob = refValue.getBytes();
                        byte[] newBlob = newValue.getBytes();
                        if (refBlob.length != newBlob.length) {
                            throw new IOException("new");
                        }
                        continue;
                    }
                    traverse(refValue, newValue);
                }
                break;
                
            case ARRAY:
                CBORArray refArray = refData.getArray();
                CBORArray newArray = newData.getArray();
                for (int q = refArray.size(); --q >= 0;) {
                    traverse(refArray.getObject(q), newArray.getObject(q));
                }
                break;
                
            default:
                if (!refData.equals(newData)) {
                    throw new IOException("hew");
                }
                newData.scan();
                break;
        }
    }

    byte[] checkForChanges(byte[] newData, byte[] refData) throws IOException {
        CBORObject newCbor = CBORObject.decode(newData);
        CBORObject refCbor = CBORObject.decode(refData);
        try {
            traverse(refCbor, newCbor);
            newCbor.checkForUnread();
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return newData;
        }
        return refData;
    }
    
}
