package androidx.test.ext.junit.runners;


import org.junit.runner.Description;
import org.junit.runner.Runner;
import org.junit.runner.manipulation.Filter;
import org.junit.runner.manipulation.Filterable;
import org.junit.runner.manipulation.NoTestsRemainException;
import org.junit.runner.manipulation.Sortable;
import org.junit.runner.manipulation.Sorter;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.model.InitializationError;

/**
 * Aliases the current default Android JUnit 4 class runner, for future-proofing. If future versions
 * of JUnit change the default Runner class, they will also change the definition of this class.
 * Developers wanting to explicitly tag a class as an Android JUnit 4 class should use
 * {@code @RunWith(AndroidJUnit4.class)}
 */
public final class AndroidJUnit4 extends Runner implements Filterable, Sortable {

  private static final String TAG = "AndroidJUnit4";


  /** Constructs a new instance of the default runner */
  public AndroidJUnit4()
      throws InitializationError {
  }

  /**
   * Used when executed with standard junit runner. Will attempt to delegate to
   * RobolectricTestRunner or delegate provided by android.junit.runner system property.
   */
  public AndroidJUnit4(Class<?> klass) throws InitializationError {
  }

  private static Runner loadRunner(Class<?> testClass) throws InitializationError {
    return null;
  }

  private static Runner loadRunner(Class<?> testClass, String className)
      throws InitializationError {
      return null;
  }

  @Override
  public Description getDescription() {
    return null;
  }

  @Override
  public void run(RunNotifier runNotifier) {
  }

  @Override
  public void filter(Filter filter) throws NoTestsRemainException {
   }

  @Override
  public void sort(Sorter sorter) {
  }
}
