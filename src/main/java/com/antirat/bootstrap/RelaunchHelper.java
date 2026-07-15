package com.antirat.bootstrap;

import java.io.IOException;
import java.util.List;

/** JDK-only bridge that starts a replacement game after the original launcher child has exited. */
public final class RelaunchHelper {
    private RelaunchHelper() {
    }

    public static void main(String[] arguments) {
        if (arguments.length != 1) {
            System.err.println("[AntiRat] Delayed relaunch helper received invalid arguments");
            return;
        }
        long parentPid;
        try {
            parentPid = Long.parseLong(arguments[0]);
        } catch (NumberFormatException invalid) {
            System.err.println("[AntiRat] Delayed relaunch helper received an invalid parent PID");
            return;
        }

        try {
            waitForExit(parentPid);
            List<String> command = AutomaticRelaunch.decodeCommand(
                    System.getenv(AutomaticRelaunch.PLAN_ENV));
            ProcessBuilder replacement = new ProcessBuilder(command);
            replacement.environment().remove(AutomaticRelaunch.PLAN_ENV);
            replacement.inheritIO();
            replacement.start();
        } catch (IOException | SecurityException failure) {
            System.err.println("[AntiRat] Delayed clean relaunch failed: "
                    + failure.getClass().getSimpleName() + ": " + failure.getMessage());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            System.err.println("[AntiRat] Delayed clean relaunch was interrupted");
        }
    }

    private static void waitForExit(long pid) throws InterruptedException {
        ProcessHandle parent = ProcessHandle.of(pid).orElse(null);
        while (parent != null && parent.isAlive()) Thread.sleep(50L);
    }
}
