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
package kaiju.tools.statuscheck;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.stream.Collectors;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.util.HelpLocation;
import ghidra.util.SystemUtilities;
import utilities.util.FileUtilities;

import kaiju.common.*;

//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = KaijuPluginPackage.NAME,
    category = PluginCategoryNames.COMMON,
    shortDescription = "Kaiju Start Check",
    description = "Checks Kaiju has everything it needs and provides tips on first start."
)
//@formatter:on
public class KaijuStatusCheckPlugin extends Plugin implements ApplicationLevelOnlyPlugin {
    private static final String TIP_INDEX = "TIP_INDEX";
    private static final String SHOW_STATUS = "SHOW_KAIJU_STATUS";

    private KaijuStatusCheckDialog dialog;
    private DockingAction action;
    
    private static boolean z3LibsFound;

    public KaijuStatusCheckPlugin(PluginTool tool) {
        super(tool);
    }
    
    static {
        try {
            KaijuNativeLibraryLoaderUtil.loadLibrary("z3");
            KaijuNativeLibraryLoaderUtil.loadLibrary("z3java");
            z3LibsFound = true;
        } catch (Throwable t) {
            z3LibsFound = false;
        }
    }

    @Override
    protected void init() {
        action = new DockingAction("Kaiju Status Check", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                dialog.doShow(tool.getToolFrame());
            }
        };
        action.setMenuBarData(new MenuData(new String[] { "&Kaiju", "Status Check" },
            ToolConstants.HELP_CONTENTS_MENU_GROUP));

        action.setEnabled(true);
        action.setHelpLocation(new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Kaiju_Status_Check"));
        tool.addAction(action);

        List<String> tips = null;
        try {
            tips = loadTips();
        }
        catch (IOException e) {
            tips = new ArrayList<>();
        }
        dialog = new KaijuStatusCheckDialog(this, tips);

        readPreferences();
    }

    private List<String> loadTips() throws IOException {
        try (InputStream in = getClass().getResourceAsStream("kaiju_tips.txt")) {
            List<String> tips = in == null ? Collections.emptyList() : FileUtilities.getLines(in);
            return tips.stream().filter(s -> s.length() > 0).collect(Collectors.toList());
        }
    }

    @Override
    protected void dispose() {
        writePreferences();

        action.dispose();
        dialog.close();
    }

    private void readPreferences() {
        String tipIndexStr = Preferences.getProperty(TIP_INDEX, "0", true);
        String showStatusStr = Preferences.getProperty(SHOW_STATUS, "true", true);

        int tipIndex = Integer.parseInt(tipIndexStr);
        final boolean showStatus = Boolean.parseBoolean(showStatusStr);
        if (showStatus) {
            tipIndex = (++tipIndex) % dialog.getNumberOfTips();
            writePreferences(tipIndex, showStatus);
        }

        dialog.setTipIndex(tipIndex);
        dialog.setShowTips(showStatus);

        SystemUtilities.runSwingLater(() -> {
            if (showStatus && !SystemUtilities.isInTestingMode()) {
                dialog.show(tool.getToolFrame());
            }
            else {
                dialog.close();
            }
        });
    }

    void writePreferences() {
        if (dialog != null) {
            writePreferences(dialog.getTipIndex(), dialog.showStatus());
        }
    }

    private void writePreferences(int tipIndex, boolean showStatus) {
        Preferences.setProperty(TIP_INDEX, "" + tipIndex);
        Preferences.setProperty(SHOW_STATUS, "" + showStatus);
        Preferences.store();
    }
}
