package fixture.reflection;

import com.antirat.guard.RuntimeHooks;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RuntimeHooksReflectionCompatibilityTest {
    @Test
    void preservesTheOriginalCallersPackageAccessForConstructorsMethodsAndFields() throws Exception {
        Constructor<PackagePrivateTarget> constructor = PackagePrivateTarget.class.getDeclaredConstructor(String.class);
        PackagePrivateTarget target = (PackagePrivateTarget) RuntimeHooks.reflectiveConstructorNewInstance(
                constructor, new Object[]{"initial"});

        Method method = PackagePrivateTarget.class.getDeclaredMethod("value");
        Field field = PackagePrivateTarget.class.getDeclaredField("value");

        assertEquals("initial", RuntimeHooks.reflectiveMethodInvoke(method, target, new Object[0]));
        RuntimeHooks.reflectiveFieldSet(field, target, "updated");
        assertEquals("updated", RuntimeHooks.reflectiveFieldGet(field, target));
    }
}

final class PackagePrivateTarget {
    String value;

    PackagePrivateTarget(String value) {
        this.value = value;
    }

    String value() {
        return value;
    }
}
