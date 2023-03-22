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
package kaiju.tools.fnhash;

import java.io.File;
import javax.swing.ImageIcon;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.action.builder.ActionBuilder;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.table.GTable;
import ghidra.app.events.ProgramSelectionPluginEvent;
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
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.SelectionNavigationAction;
import ghidra.util.table.actions.MakeProgramSelectionAction;
import ghidra.util.task.SwingUpdateManager;

import kaiju.common.*;
import kaiju.export.GTableToCSV;
import kaiju.tools.fnhashclassic.GTableToYARA;
import kaiju.tools.fnhashclassic.HeadlessToCSV;
import resources.Icons;
import resources.ResourceManager;

/**
 * Plugin that provides function hashing tools and visualizations.
 * Includes basic analysis and intersection viewer for all programs
 * in a project.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = KaijuPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "CERT Function Hashing",
    description = "Function hashing tools and visualizations.",
    servicesRequired = { GoToService.class }
)
//@formatter:on
public class FnHashPlugin extends ProgramPlugin implements DomainObjectListener, KaijuLogger {

    private static final String LAST_EXPORT_FILE = "LAST_EXPORT_DIR";

    private SelectionNavigationAction linkNavigationAction;
    private SwingUpdateManager reloadUpdateMgr;
    
    private DockingAction openFnHashAction;
    private DockingAction refreshAction;
    private DockingAction showSettingsAction;
    
    private HashViewerProvider provider;

    public FnHashPlugin(PluginTool tool) {
        //TODO: this api is marked deprecated in ghidra 10.2
        super(tool, false, false);
    }

    void doReload() {
        provider.reload();
    }

    @Override
    protected void init() {
        super.init();
        
        if (!SystemUtilities.isInHeadlessMode()) {

            this.reloadUpdateMgr = new SwingUpdateManager(100, 60000, this::doReload);
            
            this.provider = new HashViewerProvider(this);
            
            createActions();

            this.openFnHashAction = new ActionBuilder("Open Fn2Hash", getName())
                    .supportsDefaultToolContext(true)
                    .menuPath("&Kaiju", "Fn2Hash")
                    .onAction(c -> provider.setVisible(true))
                    .menuIcon(null)
                    .keyBinding("ctrl H")
                    .enabled(false)
                    .buildAndInstall(tool);
        } else {
            info(this, "Running in headless mode, use Kaiju FnHash scripts!");
        }
    }

    private void createActions() {
    
        /**
         * Refresh action
         */
        this.refreshAction = new DockingAction("Re-Analyze", getName()) {

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
        refreshAction.setDescription("Reruns the Fn2Hash analyzer on the current program");
        refreshAction.setToolBarData(new ToolBarData(refreshIcon));
        refreshAction.setHelpLocation(new HelpLocation("FnHashPlugin", "ReAnalyze"));
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
                    GTable table = ((HashViewerProvider) context.getComponentProvider()).getTable();
                    
                    int[] selectedRows = table.getSelectedRows();
                    if (selectedRows.length == 0) {
                        try {
                            HeadlessToCSV.writeCSV(file, getCurrentProgram());
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
        exportCSVAction.setHelpLocation(new HelpLocation("FnHashPlugin", "CSV"));
        tool.addLocalAction(provider, exportCSVAction);
        
        /**
         * Export to YARA
         */
        DockingAction exportYaraAction = new DockingAction("Export to YARA", getName()) {

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return getCurrentProgram() != null;
            }

            @Override
            public void actionPerformed(ActionContext context) {
                File file = chooseExportFile();
                if (file != null) {
                    GhidraTable table = ((HashViewerProvider) context.getComponentProvider()).getTable();
                    GTableToYARA.writeYARA(file, table);
                }
            }
        };
        ImageIcon arrowIcon = Icons.ARROW_DOWN_RIGHT_ICON;
        exportYaraAction.setDescription("Exports selected or entire function list to YARA format");
        exportYaraAction.setToolBarData(new ToolBarData(arrowIcon));
        exportYaraAction.setPopupMenuData(new MenuData(
            new String[] { "Export", "Export to YARA..." }, 
            ResourceManager.loadImage("images/application-vnd.oasis.opendocument.spreadsheet-template.png"),
            "Y"));
        exportYaraAction.setHelpLocation(new HelpLocation("FnHashPlugin", "YARA"));
        tool.addLocalAction(provider, exportYaraAction);
        
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
        showSettingsAction.setHelpLocation(new HelpLocation("FnHashPlugin", "Hash_Settings"));
        tool.addLocalAction(provider, showSettingsAction);

    }

    private void selectData(ProgramSelection selection) {
        ProgramSelectionPluginEvent pspe =
            new ProgramSelectionPluginEvent("Selection", selection, currentProgram);
        firePluginEvent(pspe);
        processEvent(pspe);
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
        chooser.setTitle("Choose Export File");
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
