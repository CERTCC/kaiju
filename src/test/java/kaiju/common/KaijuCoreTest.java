/***
 * CERT Kaiju
 * Copyright 2022 Carnegie Mellon University.
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

package kaiju.common.di;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.*;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.IOException;
import java.nio.file.Path;

import generic.test.AbstractGenericTest;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class KaijuCoreTest extends AbstractGenericTest {
    
    KaijuCoreTest () throws Exception {
    }
    
    @Nested
    @DisplayName("Ghidra DI tests")
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class DITests {
    
        @Test
        public void testGhidraVersionNotEmptyString() {
            assertTrue(GhidraDI.getGhidraVersionStr() != "");
        }
        
        @Test
        public void testGhidraVersionIsIntegerVersionArray() {
            Integer[] ver = GhidraDI.versionStrToIntList(GhidraDI.getGhidraVersionStr());
            assertTrue(ver.length == 3);
        }
        
        @Test
        public void testGhidraVersionStringToStringArray() {
            String[] expected = {"10", "1", "2"};
            assertArrayEquals(expected, GhidraDI.versionStrToStrList("10.1.2"));
        }
        
        @Test
        public void testGhidraVersionStringToIntegerArray() {
            Integer[] expected = {10, 1, 2};
            assertArrayEquals(expected, GhidraDI.versionStrToIntList("10.1.2"));
        }
        
        @Test
        public void testGhidraMinorVersionStringToStringArray() {
            // on brand new minor releases, Ghidra seems to only use two digits, e.g., "10.2",
            // so check that we're adding a "0" to the third spot in the array
            String[] expected = {"10", "2", "0"};
            assertArrayEquals(expected, GhidraDI.versionStrToStrList("10.2"));
        }
        
        @Test
        public void testAtLeastGivenMinorGhidraVersion() {
            Integer[] expected = {10, 1, 2};
            // should pass if same
            assertTrue(GhidraDI.compareGhidraVersions(expected, expected, "minor") >= 0);
            // should pass if minor version is bigger
            Integer[] newer = {10, 2, 2};
            assertTrue(GhidraDI.compareGhidraVersions(newer, expected, "minor") >= 0);
            // should fail if minor version is older
            Integer[] older = {10, 0, 2};
            assertFalse(GhidraDI.compareGhidraVersions(older, expected, "minor") >= 0);
        }
    
    }

}
