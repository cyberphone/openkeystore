package androidx.test.platform.app;

import android.content.Context;

public class InstrumentationRegistry {
    
    public Context getTargetContext() {
        return null;
    }
    
    public static InstrumentationRegistry getInstrumentation() {
        return new InstrumentationRegistry();
    }
    
}
