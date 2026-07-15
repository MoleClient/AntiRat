package com.antirat.scan;

import com.antirat.config.AntiRatConfig;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RealBenignCorpusTest {
    @Test
    void scansDownloadedPopularFabricModsWithoutAutomaticQuarantine() throws Exception {
        String configured = System.getProperty("antirat.benignCorpusDir", "");
        Assumptions.assumeTrue(!configured.isBlank(), "external benign corpus not configured");
        Path directory = Path.of(configured);
        Assumptions.assumeTrue(Files.isDirectory(directory), "external benign corpus directory is missing");

        List<Path> jars;
        try (Stream<Path> paths = Files.list(directory)) {
            jars = paths.filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".jar"))
                    .sorted(Comparator.comparing(path -> path.getFileName().toString()))
                    .toList();
        }
        int minimum = Integer.getInteger("antirat.benignCorpusMinimum", 10);
        assertTrue(jars.size() >= minimum, "real benign corpus is unexpectedly small");

        JarScanner scanner = new JarScanner(AntiRatConfig.defaults());
        List<String> failures = new ArrayList<>();
        long suiteStart = System.nanoTime();
        for (Path jar : jars) {
            long started = System.nanoTime();
            ScanResult result = scanner.scan(jar);
            long millis = (System.nanoTime() - started) / 1_000_000L;
            System.out.printf(Locale.ROOT, "BENIGN_CORPUS\t%s\tscore=%d\trisk=%s\tquarantine=%s\tclasses=%d\tms=%d%n",
                    jar.getFileName(), result.score(), result.riskLevel(), result.quarantineRecommended(),
                    result.classCount(), millis);
            if (result.quarantineRecommended()) failures.add(jar.getFileName() + " => " + result.evidence());
        }
        long totalMillis = (System.nanoTime() - suiteStart) / 1_000_000L;
        System.out.printf(Locale.ROOT, "BENIGN_CORPUS_TOTAL\tjars=%d\tms=%d%n", jars.size(), totalMillis);
        assertFalse(!failures.isEmpty(), "false-positive quarantines: " + failures);
    }
}
