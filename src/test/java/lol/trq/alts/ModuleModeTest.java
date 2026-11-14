package lol.trq.alts;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * The suite runs twice: on the class path ({@code test}) and with the library as a named module on the module
 * path ({@code moduleTest}, which sets {@code lol.trq.alts.expectModule}). This pins that each run is the one
 * it claims to be, so a module-path run that quietly fell back to the class path cannot pass for one.
 */
class ModuleModeTest {

    @Test
    void theLibraryIsANamedModuleExactlyWhenTheRunSaysSo() {
        boolean expected = Boolean.getBoolean("lol.trq.alts.expectModule");

        assertEquals(expected, AltsRuntime.class.getModule().isNamed());
        if (expected) {
            assertEquals("lol.trq.alts", AltsRuntime.class.getModule().getName());
            assertEquals(true, com.google.gson.Gson.class.getModule().isNamed(), "Gson resolves as a module");
        }
    }
}
