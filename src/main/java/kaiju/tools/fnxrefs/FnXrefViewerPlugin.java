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
package kaiju.tools.fnxrefs;

import java.io.File;
import java.lang.reflect.*;
import javax.swing.ImageIcon;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.table.GTable;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.data.DataSettingsDialog;
import ghidra.app.services.GoToService;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ChangeManager;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.SelectionNavigationAction;
import ghidra.util.table.actions.MakeProgramSelectionAction;
import ghidra.util.task.SwingUpdateManager;
import kaiju.common.di.GhidraDI;
import kaiju.common.KaijuLogger;
import kaiju.common.KaijuPluginPackage;
import kaiju.export.GTableToCSV;
import resources.Icons;
import resources.ResourceManager;

/**
 * Plugin that provides an X-Refs (cross-references) table, addresses in a given Program
 * that are referenced by other data and/or code in the Program.
 * <p>
 *
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = KaijuPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "CERT Program Function Xref Viewer",
    description = "View function data and instruction cross-references (X-Refs) for a single program.",
    servicesRequired = { GoToService.class }
)
//@formatter:on
public class FnXrefViewerPlugin extends ProgramPlugin implements DomainObjectListener, KaijuLogger {

    private DockingAction showSettingsAction;
    private SelectionNavigationAction linkNavigationAction;
    private FnXrefViewerProvider provider;
    private SwingUpdateManager reloadUpdateMgr;
    
    private static final String LAST_EXPORT_FILE = "LAST_EXPORT_DIR";

    public FnXrefViewerPlugin(PluginTool tool) {
        super(tool, false, false);
    }

    void doReload() {
        provider.reload();
    }

    @Override
    protected void init() {
        super.init();

        provider = new FnXrefViewerProvider(this);
        reloadUpdateMgr = new SwingUpdateManager(100, 60000, this::doReload);
        createActions();
    }

    private void createActions() {
    
        /**
         * Refresh action
         */
        DockingAction refreshAction = new DockingAction("Re-Analyze", getName()) {

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return getCurrentProgram() != null;
            }

            @Override
            public void actionPerformed(ActionContext context) {
                reload();
            }
        };
        ImageIcon refreshIcon = Icons.REFRESH_ICON;
        refreshAction.setDescription("Reruns the FnXref analyzer on the current program");
        refreshAction.setToolBarData(new ToolBarData(refreshIcon));
        refreshAction.setHelpLocation(new HelpLocation("FnXrefViewerPlugin", "ReAnalyze"));
        tool.addLocalAction(provider, refreshAction);
        
        /**
         * Export to CSV
         */
        DockingAction exportCSVAction = new DockingAction("Export To CSV", getName()) {

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return getCurrentProgram() != null;
            }

            @Override
            public void actionPerformed(ActionContext context) {
                File file = chooseExportFile();
                if (file != null) {
                    GTable table = ((FnXrefViewerProvider) context.getComponentProvider()).getTable();
                    
                    int[] selectedRows = table.getSelectedRows();
                    if (selectedRows.length == 0) {
                        // TODO: check if headless or GUI mode that just wants to export everything
                        try {
                            HeadlessXrefsToCSV.writeCSV(file, getCurrentProgram());
                        } catch (Exception e) {
                            // TODO: do nothing?
                        }
                    } else {
                        GTableToCSV.writeCSV(file, table);
                    }
                    //reload();
                }
            }
        };
        ImageIcon arrowIconC = Icons.ARROW_DOWN_RIGHT_ICON;
        exportCSVAction.setDescription("Exports selected or entire function list to CSV format");
        exportCSVAction.setToolBarData(new ToolBarData(arrowIconC));
        exportCSVAction.setPopupMenuData(new MenuData(
            new String[] { "Export", "Export to CSV..." }, 
            ResourceManager.loadImage("images/application-vnd.oasis.opendocument.spreadsheet-template.png"),
            "Y"));
        exportCSVAction.setHelpLocation(new HelpLocation("FnXrefViewerPlugin", "CSV"));
        tool.addLocalAction(provider, exportCSVAction);
        
        /**
         * Program selection
         */
        tool.addLocalAction(provider, new MakeProgramSelectionAction(this, provider.getTable()));

        linkNavigationAction = new SelectionNavigationAction(this, provider.getTable());
        tool.addLocalAction(provider, linkNavigationAction);
        
        // settings widget
        showSettingsAction = new DockingAction("Settings", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                try {
                    DataSettingsDialog dialog = new DataSettingsDialog(currentProgram, provider.selectData());

                    tool.showDialog(dialog);
                    dialog.dispose();
                }
                catch (CancelledException e) {
                    // TODO: do nothing?
                }
            }

        };
        showSettingsAction.setPopupMenuData(new MenuData(new String[] { "Settings..." }, "R"));
        showSettingsAction.setDescription("Shows settings for the selected strings");
        showSettingsAction.setHelpLocation(new HelpLocation("FnXrefViewerPlugin", "Hash_Settings"));
        tool.addLocalAction(provider, showSettingsAction);

    }

    @Override
    public void dispose() {
        reloadUpdateMgr.dispose();
        provider.dispose();
        super.dispose();
    }

    @Override
    protected void programDeactivated(Program program) {
        program.removeListener(this);
        provider.setProgram(null);
    }

    @Override
    protected void programActivated(Program program) {
        program.addListener(this);
        provider.setProgram(program);
    }

    @Override
    protected void locationChanged(ProgramLocation loc) {
        if (linkNavigationAction.isSelected() && loc != null) {
            provider.setProgram(loc.getProgram());
            provider.showProgramLocation(loc);
        }
    }

    @Override
    public void domainObjectChanged(DomainObjectChangedEvent ev) {
        if (ev.containsEvent(DomainObject.DO_OBJECT_RESTORED) ||
            ev.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_MOVED) ||
            ev.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_REMOVED) ||
            ev.containsEvent(ChangeManager.DOCR_FUNCTION_REMOVED) ||
            ev.containsEvent(ChangeManager.DOCR_DATA_TYPE_CHANGED)) {
            
                reload();

        }
        else if (ev.containsEvent(ChangeManager.DOCR_CODE_ADDED)) {
            for (int i = 0; i < ev.numRecords(); ++i) {
                DomainObjectChangeRecord doRecord = ev.getChangeRecord(i);
                Object newValue = doRecord.getNewValue();
                switch (doRecord.getEventType()) {
                    case ChangeManager.DOCR_FUNCTION_REMOVED:
                        ProgramChangeRecord pcRec = (ProgramChangeRecord) doRecord;
                        provider.remove(pcRec.getStart(), pcRec.getEnd());
                        break;
                    case ChangeManager.DOCR_FUNCTION_ADDED:
                        if (newValue instanceof Function) {
                            provider.add((Function) newValue);
                        }
                        break;
                    default:
                        //Msg.info(this, "Unhandled event type: " + doRecord.getEventType());
                        break;
                }
            }
        }
        else if (ev.containsEvent(ChangeManager.DOCR_DATA_TYPE_SETTING_CHANGED)) {
            // Unusual code: because the table model goes directly to the settings values
            // during each repaint, we don't need to figure out which row was changed.
            provider.getComponent().repaint();
        }
    }

    void reload() {
        reloadUpdateMgr.update();
    }
    
    private GhidraFileChooser createExportFileChooser() {
        GhidraFileChooser chooser = new GhidraFileChooser(provider.getComponent());
        chooser.setTitle("Choose Function XREFS Export File");
        chooser.setApproveButtonText("OK");

        String filepath = Preferences.getProperty(LAST_EXPORT_FILE);
        if (filepath != null) {
            chooser.setSelectedFile(new File(filepath));
        }

        return chooser;
    }

    private File chooseExportFile() {
        debug(this, "Starting file selection dialog, waiting for user.");
        GhidraFileChooser chooser = createExportFileChooser();
        File file = chooser.getSelectedFile();
        if (file == null) {
            return null;
        }
        if (file.exists()) {
            int result = OptionDialog.showYesNoDialog(provider.getComponent(), "Overwrite?",
                "File exists. Do you want to overwrite?");

            if (result != OptionDialog.OPTION_ONE) {
                return null;
            }
        }
        storeLastExportDirectory(file);
        return file;
    }

    private void storeLastExportDirectory(File file) {
        Preferences.setProperty(LAST_EXPORT_FILE, file.getAbsolutePath());
        Preferences.store();
    }
}
