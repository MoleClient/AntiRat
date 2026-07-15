package com.antirat.scan;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

final class ClassFileInspector {
    private static final int MAX_CAPTURED_UTF_BYTES = 2 * 1024 * 1024;

    private ClassFileInspector() {
    }

    static Result inspect(byte[] bytes) throws IOException {
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(bytes))) {
            if (input.readInt() != 0xCAFEBABE) {
                throw new IOException("invalid class-file magic");
            }
            input.readUnsignedShort();
            int major = input.readUnsignedShort();
            int count = input.readUnsignedShort();
            List<String> utf8 = new ArrayList<>(Math.min(count, 512));
            int captured = 0;

            for (int index = 1; index < count; index++) {
                int tag = input.readUnsignedByte();
                switch (tag) {
                    case 1 -> {
                        String value = input.readUTF();
                        captured += value.length();
                        if (captured <= MAX_CAPTURED_UTF_BYTES) utf8.add(value);
                    }
                    case 3, 4 -> skipFully(input, 4);
                    case 5, 6 -> {
                        skipFully(input, 8);
                        index++;
                    }
                    case 7, 8, 16, 19, 20 -> skipFully(input, 2);
                    case 9, 10, 11, 12, 17, 18 -> skipFully(input, 4);
                    case 15 -> skipFully(input, 3);
                    default -> throw new IOException("unsupported constant-pool tag " + tag);
                }
            }
            return new Result(List.copyOf(utf8), major);
        } catch (EOFException exception) {
            throw new IOException("truncated class file", exception);
        }
    }

    private static void skipFully(DataInputStream input, int length) throws IOException {
        int remaining = length;
        while (remaining > 0) {
            int skipped = input.skipBytes(remaining);
            if (skipped <= 0) throw new EOFException();
            remaining -= skipped;
        }
    }

    record Result(List<String> utf8, int majorVersion) {
    }
}
