package android.content;

import java.io.InputStream;
import java.io.OutputStream;

public class Context {
    
    public static int MODE_PRIVATE = 0;
    
    public String getContentResolver() {
        return null;
    }
    
    public InputStream openFileInput(String file) {
        return null;
    }

    public OutputStream openFileOutput(String file, int mode) {
        return null;
    }
}
