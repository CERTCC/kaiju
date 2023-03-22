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
package kaiju.common.logging;

import docking.framework.DockingApplicationConfiguration;
import ghidra.util.ErrorLogger;
import ghidra.util.Msg;

/**
 * Provides easy utility to direct messages to multiple locations at
 * once -- by default, the Ghidra console and system log, but also
 * the GUI via pop-up message boxes if requested.
 * To properly support plugins in both GUI and headless mode, user
 * feedback needs to be directed to more than one location so that
 * all use modes are covered. Ghidra does not provide an out-of-the-box
 * class that does this.
 * Message Boxes are based on ghidra.util.Msg:
 * https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html
 */
public class MultiLogger implements ErrorLogger {

    // this really represents the logging level for the GUI;
    // as in, how sensitive do you want it to be with pop up messages?
    private MultiLogLevel level;
    
    private boolean isGUI;
    
    private boolean logLevelIsGreater(MultiLogLevel b) {
        return level.compareTo(b) >= 0;
    }
    
    // makes this a singleton pattern class
    private static MultiLogger single_instance = null; 
    
    /**
     * For use in code such as analyzers that has no GUI tool it is
     * associated with.
     */
    private MultiLogger() {
        super();
        // set a default log level for displaying GUI messages
        level = MultiLogLevel.ERROR;
        // set if GUI or headless, shouldn't change during running process?
        DockingApplicationConfiguration config = new DockingApplicationConfiguration();
        isGUI = !config.isHeadless();
    }
    
    public static MultiLogger getInstance() {
        if (single_instance == null) 
            single_instance = new MultiLogger(); 
  
        return single_instance; 
    }
    
    public void setLogLevel(MultiLogLevel new_level) {
        level = new_level;
    }

    @Override
    public void debug(Object originator, Object message) {
        // NOTE: debug info never goes to a GUI pop up message?
        Msg.debug(originator, message);
    }

    @Override
    public void debug(Object originator, Object message, Throwable throwable) {
        // NOTE: debug info never goes to a GUI pop up message?
        Msg.debug(originator, message, throwable);
    }

    @Override
    public void error(Object originator, Object message) {
        Msg.error(originator, message);
    }

    @Override
    public void error(Object originator, Object message, Throwable throwable) {
        Msg.error(originator, message, throwable);
    }
    
    public void errorUsingGui(Object originator, Object message) {
        if (isGUI && logLevelIsGreater(MultiLogLevel.ERROR)) {
            Msg.showError(originator, null, "Kaiju Error", message);
        } else {
            Msg.error(originator, message);
        }
    }

    public void errorUsingGui(Object originator, Object message, Throwable throwable) {
        if (isGUI && logLevelIsGreater(MultiLogLevel.ERROR)) {
            // Ghidra 9.2 appears to have removed the variant with a throwable
            Msg.showError(originator, null, "Kaiju Error", message);
        } else {
            Msg.error(originator, message, throwable);
        }
    }

    @Override
    public void info(Object originator, Object message) {
        Msg.info(originator, message);
    }

    @Override
    public void info(Object originator, Object message, Throwable throwable) {
        Msg.info(originator, message, throwable);
    }
    
    public void infoUsingGui(Object originator, Object message) {
        if (isGUI && logLevelIsGreater(MultiLogLevel.INFO)) {
            Msg.showInfo(originator, null, "Kaiju Notification", message);
        } else {
            Msg.info(originator, message);
        }
    }

    public void infoUsingGui(Object originator, Object message, Throwable throwable) {
        if (isGUI && logLevelIsGreater(MultiLogLevel.INFO)) {
            // NOTE: showInfo doesn't seem to have a variant with a throwable
            Msg.showInfo(originator, null, "Kaiju Notification", message);
        } else {
            Msg.info(originator, message, throwable);
        }
    }

    @Override
    public void trace(Object originator, Object message) {
        // NOTE: trace never goes to a GUI pop up message?
        Msg.trace(originator, message);
    }

    @Override
    public void trace(Object originator, Object message, Throwable throwable) {
        // NOTE: trace never goes to a GUI pop up message?
        Msg.trace(originator, message, throwable);
    }

    @Override
    public void warn(Object originator, Object message) {
        Msg.warn(originator, message);
    }

    @Override
    public void warn(Object originator, Object message, Throwable throwable) {
        Msg.warn(originator, message, throwable);
    }
    
    public void warnUsingGui(Object originator, Object message) {
        if (isGUI && logLevelIsGreater(MultiLogLevel.WARN)) {
            Msg.showWarn(originator, null, "Kaiju Warning", message);
        } else {
            Msg.warn(originator, message);
        }
    }

    public void warnUsingGui(Object originator, Object message, Throwable throwable) {
        if (isGUI && logLevelIsGreater(MultiLogLevel.WARN)) {
            // Ghidra 9.2 appears to have removed the variant with a throwable
            Msg.showWarn(originator, null, "Kaiju Warning", message);
        } else {
            Msg.warn(originator, message, throwable);
        }
    }
} 
