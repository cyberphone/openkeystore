package cbor_api_demo;

import org.webpki.cbor.CBORDecoder;
import org.webpki.cbor.CBORInt;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORString;
import org.webpki.cbor.CBORTag;
import org.webpki.cbor.CBORTypedObjectDecoder;
import org.webpki.cbor.CBORTypedObjectDecoderCache;

public class TypedObjectsDemo {
    
    // Typed object decoder one.
    public static class ObjectOne extends CBORTypedObjectDecoder {

        int number;
        
        static final String OBJECT_ID   = "https://example.com/object-one";
        static final CBORObject INT_KEY = new CBORInt(1);
        
        @Override
        protected void decode(CBORObject cborBody) {
            number = cborBody.getMap().get(INT_KEY).getInt32();
        }

        @Override
        public String getObjectId() {
            return OBJECT_ID;
        }
    }
    
    // Typed object decoder two.
    public static class ObjectTwo extends CBORTypedObjectDecoder {
        
        static final String OBJECT_ID = "https://example.com/object-two";
        
        String justAString;

        @Override
        protected void decode(CBORObject cborBody) {
            justAString = cborBody.getString();
        }

        @Override
        public String getObjectId() {
            return OBJECT_ID;
        }
    }
    
    // Register the object decoders.
    static final CBORTypedObjectDecoderCache decoderCache = new CBORTypedObjectDecoderCache()
            .addToCache(ObjectOne.class)
            .addToCache(ObjectTwo.class);

    
    public static void main(String[] args) {
        // Create typed CBOR messages.
        byte[] objectOne = new CBORTag(ObjectOne.OBJECT_ID,
                new CBORMap().set(ObjectOne.INT_KEY, new CBORInt(-343)))
                    .encode();
        
        byte[] objectTwo = new CBORTag(ObjectTwo.OBJECT_ID, 
                new CBORString("Hi there!"))
                    .encode();
        
        // Decode and instantiate.
        CBORTypedObjectDecoder decodedObject = decoderCache.decode(
                CBORDecoder.decode(objectOne));
        
        // Dispatch to the proper handler for the associated decoder.
        switch (decodedObject.getObjectId()) {
            case ObjectOne.OBJECT_ID:
                System.out.println("Number=" + ((ObjectOne)decodedObject).number);
                break;
                
            default: 
                throw new RuntimeException("Unexpected");
        }
//@begin@
new CborDocumentLog(args[0], "#sample.program.diagnostic#", CBORDecoder.decode(objectOne));
new CborDocumentLog(args[0], args[1], "#sample.program#");
//@end@
    }
}
