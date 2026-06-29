package android.util;

public class Half {
    public static short toHalf(float f) {
        return Float.floatToFloat16(f);
    }
    public static float toFloat(short half) {
        return Float.float16ToFloat(half);
    }
}
