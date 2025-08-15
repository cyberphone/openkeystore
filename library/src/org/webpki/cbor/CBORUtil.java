package org.webpki.cbor;

public class CBORUtil {

    private CBORUtil() {} 

    public static byte[] concatByteArrays(byte[]...listOfArrays) {
        int totalLength = 0;
        for (byte[] array : listOfArrays) {
            totalLength += array.length;
        }
        byte[] result = new byte[totalLength];
        int currentIndex = 0;
        for (byte[] array : listOfArrays) {
            System.arraycopy(array, 0, result, currentIndex, array.length);
            currentIndex += array.length;
        }
        return result;
    }

    public static byte[] unsignedLongToByteArray(long value) {
        long temp = value;
        int length = 0;
        do {
            length++;
        } while ((temp >>>= 8) != 0);
        byte[] result = new byte[length];
        while (--length >= 0) {
            result[length] = (byte)value;
            value >>>= 8;
        }
        return result;
    }

    public static long reverseBits(long bits, int fieldWidth) {
        long reversed = 0;
        int bitCount = 0;
        while (bits > 0) {
            bitCount++;
            reversed <<= 1;
            if ((bits & 1) == 1)
                reversed |= 1;
            bits >>= 1;
        }
        if (bitCount > fieldWidth) {
            throw new IllegalArgumentException("Field exceeds fieldWidth");
        }
        return reversed << (fieldWidth - bitCount);
    }
}
