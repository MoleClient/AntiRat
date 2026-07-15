package com.antirat.client;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.imageio.ImageIO;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class AntiRatThreatScreenTest {
    @Test
    void popupNeverRequestsMinecraftsOncePerFrameBackgroundBlur() throws Exception {
        AtomicBoolean callsRenderBackground = new AtomicBoolean();
        try (InputStream bytes = AntiRatThreatScreen.class.getResourceAsStream("AntiRatThreatScreen.class")) {
            assertNotNull(bytes);
            new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM9) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                 String signature, String[] exceptions) {
                    if (!name.equals("render")) return null;
                    return new MethodVisitor(Opcodes.ASM9) {
                        @Override
                        public void visitMethodInsn(int opcode, String owner, String calledName,
                                                    String calledDescriptor, boolean isInterface) {
                            if (calledName.equals("renderBackground")) callsRenderBackground.set(true);
                        }
                    };
                }
            }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        }
        assertFalse(callsRenderBackground.get(),
                "Threat popup must not trigger Minecraft's once-per-frame blur a second time");
    }

    @Test
    void logoIsSquarePackagedAndDeclaredAsTheFabricModIcon() throws Exception {
        try (InputStream logoBytes = AntiRatThreatScreen.class.getResourceAsStream(
                "/assets/antirat/textures/gui/icon.png")) {
            assertNotNull(logoBytes);
            var image = ImageIO.read(logoBytes);
            assertNotNull(image);
            org.junit.jupiter.api.Assertions.assertEquals(256, image.getWidth());
            org.junit.jupiter.api.Assertions.assertEquals(256, image.getHeight());
        }
        try (InputStream metadata = AntiRatThreatScreen.class.getResourceAsStream("/fabric.mod.json")) {
            assertNotNull(metadata);
            String json = new String(metadata.readAllBytes(), StandardCharsets.UTF_8);
            org.junit.jupiter.api.Assertions.assertTrue(
                    json.contains("\"icon\": \"assets/antirat/textures/gui/icon.png\""));
        }
    }
}
