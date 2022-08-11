/***
 * CERT Kaiju
 * Copyright 2021 Carnegie Mellon University.
 *
 * NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
 * INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY
 * MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER
 * INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR
 * MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL.
 * CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT
 * TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
 *
 * Released under a BSD (SEI)-style license, please see LICENSE.md or contact permission@sei.cmu.edu for full terms.
 *
 * [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.
 * Please see Copyright notice for non-US Government use and distribution.
 *
 * Carnegie Mellon (R) and CERT (R) are registered in the U.S. Patent and Trademark Office by Carnegie Mellon University.
 *
 * This Software includes and/or makes use of the following Third-Party Software subject to its own license:
 * 1. OpenJDK (http://openjdk.java.net/legal/gplv2+ce.html) Copyright 2021 Oracle.
 * 2. Ghidra (https://github.com/NationalSecurityAgency/ghidra/blob/master/LICENSE) Copyright 2021 National Security Administration.
 * 3. GSON (https://github.com/google/gson/blob/master/LICENSE) Copyright 2020 Google.
 * 4. JUnit (https://github.com/junit-team/junit5/blob/main/LICENSE.md) Copyright 2020 JUnit Team.
 * 5. Gradle (https://github.com/gradle/gradle/blob/master/LICENSE) Copyright 2021 Gradle Inc.
 * 6. markdown-gradle-plugin (https://github.com/kordamp/markdown-gradle-plugin/blob/master/LICENSE.txt) Copyright 2020 Andres Almiray.
 * 7. Z3 (https://github.com/Z3Prover/z3/blob/master/LICENSE.txt) Copyright 2021 Microsoft Corporation.
 * 8. jopt-simple (https://github.com/jopt-simple/jopt-simple/blob/master/LICENSE.txt) Copyright 2021 Paul R. Holser, Jr.
 *
 * DM21-0792
 */

package kaiju.ooanalyzer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import resources.ResourceManager;

// For some reason, gradle can't find JUnit tests in a class that extends
// AbstractGhidraHeadedIntegrationTest.  So we'll make the JUnit tests in this class and call
// OOAnalyzerTest
class OOAnalyzerTestHelper {

    final private String testNameSeparator = "_";

    //private OOAnalyzerTest ooatest;
    private Set<Path> testJsons;

    private Path exeDirectory;
    private Path jsonDirectory;

    OOAnalyzerTestHelper () throws java.io.IOException {
        
        // get the directory from the environment variable KAIJU_AUTOCATS_DIR
        // at this point, gradle should have checked that this is a real path, so just use it
        // TODO: is there a better way to confirm this is an AUTOCATS path first?
        String autocatsDirString = System.getenv("KAIJU_AUTOCATS_DIR");
        Path autocatsTopDirectory = Path.of(autocatsDirString);
        
        // WARNING: these directories are hard-coded and must be updated if changed
        jsonDirectory = ResourceManager.getResourceFile("ooanalyzer/").toPath();
        // the exe directory should have two subdirectories to match the test/resources/ooanalyzer/ directory
        exeDirectory = autocatsTopDirectory.resolve("exe");
        testJsons =
        Files.find(jsonDirectory, 999, (p, bfa) -> p.getFileName ().toString ().endsWith (".json") && bfa.isRegularFile ())
            .collect(Collectors.toSet ());
    }

    @TestFactory
    public Stream<DynamicTest> makeTests () {
        return testJsons.stream ()
            .flatMap (json -> {
                var testName = jsonDirectory.relativize (json);
                var exe = Paths.get (exeDirectory.resolve (testName).toString ().replace (".json", ".exe"));

                return (Arrays.asList(new Boolean[] { true, false })
                            .stream ().map (useNs -> {
                                var name = testName.toString () + testNameSeparator + (useNs ? "useNs" : "noUseNs");
                                return DynamicTest.dynamicTest(name, () ->
                                        {
                                            OOAnalyzerTest ooatest = new OOAnalyzerTest();
                                            ooatest.doTest(exe, json, useNs);
                                        });
                        }));

            });
    }
}
