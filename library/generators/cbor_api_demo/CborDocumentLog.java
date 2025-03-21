package cbor_api_demo;

import org.webpki.cbor.CBORArray;
import org.webpki.cbor.CBORBytes;
import org.webpki.cbor.CBORDecoder;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;

import org.webpki.util.HexaDecimal;

public class CborDocumentLog {
    
    CborDocumentLog(String fileName, String holder, byte[] binaryData) {
        ReadWriteSubstitute.replace(fileName, 
                                    holder,
                                    HexaDecimal.encode(binaryData));
    }

    CborDocumentLog(String fileName, String holder, CBORObject cbor) {
        ReadWriteSubstitute.replace(fileName, 
                                    holder,
                                    ReadWriteSubstitute.htmlIze(cbor.toString()));
    }

    CborDocumentLog(String fileName, String sourceCodeFile, String holder) {
        String source = ReadWriteSubstitute.readString(sourceCodeFile);
        int i;
        while ((i = source.indexOf("//@begin@")) >= 0)
        source = source.substring(0, i) +
                source.substring(source.indexOf("//@end@\n") + 8);
        ReadWriteSubstitute.replace(fileName, 
                holder,
                ReadWriteSubstitute.htmlIze(source));
    }

    CborDocumentLog() {
        // TODO Auto-generated constructor stub
    }
    
    void traverse(CBORObject refData, CBORObject newData) {
        switch (refData) {
            case CBORMap refMap:
                CBORMap newMap = newData.getMap();
                for (CBORObject key : refMap.getKeys()) {
                    CBORObject refValue = refMap.get(key);
                    CBORObject newValue = newMap.get(key);
                    if (refValue instanceof CBORBytes) {
                        byte[] refBlob = refValue.getBytes();
                        byte[] newBlob = newValue.getBytes();
                        if (refBlob.length != newBlob.length) {
                            throw new RuntimeException("new");
                        }
                        continue;
                    }
                    traverse(refValue, newValue);
                }
                break;
                
            case CBORArray refArray:
                CBORArray newArray = newData.getArray();
                for (int q = refArray.size(); --q >= 0;) {
                    traverse(refArray.get(q), newArray.get(q));
                }
                break;
                
            default:
                if (!refData.equals(newData)) {
                    throw new RuntimeException("hew");
                }
                newData.scan();
                break;
        }
    }

    byte[] checkForChanges(byte[] newData, byte[] refData) {
        CBORObject newCbor = CBORDecoder.decode(newData);
        CBORObject refCbor = CBORDecoder.decode(refData);
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
