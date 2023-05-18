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

//import static org.junit.Assert.assertTrue;

import java.nio.file.Path;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.Msg;
import kaiju.common.di.GhidraDI;
import kaiju.tools.ooanalyzer.OOAnalyzerGhidraPlugin;

class OOAnalyzerTest extends AbstractGhidraHeadedIntegrationTest {

    private TestEnv env;
    private OOAnalyzerGhidraPlugin plugin;
    
    OOAnalyzerTest () throws Exception {
    }

    public void doTest (Path exe, Path json, Boolean useNs) throws Exception {
        env = new TestEnv();
        setErrorGUIEnabled (false);

        // Import the program
        Program p = env.getGhidraProject ().importProgram (exe.toFile ());

        // Open in the tool
        env.open (p);

        // Analyze it
        // NOTE: get heap exhaustion errors when doing analysis with Fn2Hash, etc.
        // Not necessary to analyze to check JSON importer, but consider
        // for future tests.
        //env.getGhidraProject ().analyze (p, false);

        // And mark it as analyzed?  Ok ghidra whatever.
        GhidraProgramUtilities.markProgramAnalyzed(p);

        plugin = env.addPlugin(OOAnalyzerGhidraPlugin.class);

        // Import json.
        OOAnalyzerGhidraPlugin.ImportCommand cmd = plugin.configureAndExecute (json.toFile (), useNs);

        // Use a semaphore or something. Get the tool's TaskMonitor?
        while (!cmd.getCompleted ()) {
            Msg.debug (this, "Sleeping until completed.");
            Thread.sleep(1000);
        }

        Msg.info (this, "We didn't crash!");

        env.close (p);
        
        env.dispose ();

    }

}
