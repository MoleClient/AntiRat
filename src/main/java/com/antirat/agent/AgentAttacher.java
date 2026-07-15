package com.antirat.agent;

import com.sun.tools.attach.VirtualMachine;

/** Short-lived helper used when the bundled JDK supports dynamic attach. */
public final class AgentAttacher {
    private AgentAttacher() {
    }

    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 2 || !arguments[0].matches("[0-9]+")) {
            throw new IllegalArgumentException("expected target pid and agent JAR");
        }
        VirtualMachine machine = VirtualMachine.attach(arguments[0]);
        try {
            machine.loadAgent(arguments[1], "");
        } finally {
            machine.detach();
        }
    }
}
