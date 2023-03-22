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

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;

import javax.swing.ImageIcon;
import javax.swing.JComponent;
import javax.swing.JPanel;

import docking.ActionContext;
import docking.widgets.table.threaded.ThreadedTableModelListener;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.GhidraThreadedTablePanel;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

/**
 * Provider for the defined strings table.
 */
public class HashViewerProvider extends ComponentProviderAdapter {

    public static final ImageIcon ICON = ResourceManager.loadImage("images/dataW.gif");

    private GhidraThreadedTablePanel<ProgramLocation> threadedTablePanel;
    private GhidraTableFilterPanel<ProgramLocation> filterPanel;
    private GhidraTable table;
    private HashViewerTableModel hashModel;
    private JComponent mainPanel;
    private Program currentProgram;
    private HelpLocation helpLocation;
    private AtomicReference<ProgramLocation> delayedShowProgramLocation = new AtomicReference<>();

    HashViewerProvider(FnHashPlugin plugin) {
        super(plugin.getTool(), "CERT Function Hash Viewer", plugin.getName());
        mainPanel = createWorkPanel();
        setIcon(ICON);
        helpLocation = new HelpLocation(plugin.getName(), plugin.getName());
        addToTool();
    }

    @Override
    public void componentHidden() {
        hashModel.reload(null);
    }

    @Override
    public void componentShown() {
        hashModel.reload(currentProgram);
    }

    @Override
    public ActionContext getActionContext(MouseEvent event) {
        return new HashViewerContext(this, table);
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    /*
     * @see ghidra.framework.docking.HelpTopic#getHelpLocation()
     */
    @Override
    public HelpLocation getHelpLocation() {
        return helpLocation;
    }

    void setProgram(Program program) {
        if (program == currentProgram) {
            return;
        }
        currentProgram = program;
        delayedShowProgramLocation.set(null);
        if (isVisible()) {
            hashModel.reload(program);
        }
    }

    void dispose() {
        currentProgram = null;
        removeFromTool();
        threadedTablePanel.dispose();
        filterPanel.dispose();
    }

    private JComponent createWorkPanel() {

        hashModel = new HashViewerTableModel(tool);

        threadedTablePanel = new GhidraThreadedTablePanel<>(hashModel, 1000);
        table = threadedTablePanel.getTable();
        table.setName("FnHashDataTable");
        table.setPreferredScrollableViewportSize(new Dimension(350, 150));
        table.getSelectionModel().addListSelectionListener(e -> notifyContextChanged());

        hashModel.addTableModelListener(e -> {
            int rowCount = hashModel.getRowCount();
            int unfilteredCount = hashModel.getUnfilteredRowCount();

            setSubTitle("" + rowCount + " functions" +
                (rowCount != unfilteredCount ? " (of " + unfilteredCount + ")" : ""));
        });

        hashModel.addThreadedTableModelListener(new ThreadedTableModelListener() {

            @Override
            public void loadingStarted() {
                // ignore
            }

            @Override
            public void loadingFinished(boolean wasCancelled) {
                // loadingFinished gets called when the table is empty
                // and then when it finishes loading.
                // Only de-queue the delayedProgramLocation if we have records in the model.
                if (hashModel.getRowCount() != 0) {
                    ProgramLocation delayedProgLoc = delayedShowProgramLocation.getAndSet(null);
                    if (delayedProgLoc != null) {
                        doShowProgramLocation(delayedProgLoc);
                    }
                }
            }

            @Override
            public void loadPending() {
                // ignore
            }
        });

        GoToService goToService = tool.getService(GoToService.class);
        table.installNavigation(goToService, goToService.getDefaultNavigatable());

        filterPanel = new GhidraTableFilterPanel<>(table, hashModel);

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(threadedTablePanel, BorderLayout.CENTER);
        panel.add(filterPanel, BorderLayout.SOUTH);

        return panel;
    }

    private void notifyContextChanged() {
        tool.contextChanged(this);
    }

    ProgramSelection selectData() {
        return table.getProgramSelection();
    }

    void add(Function data) {
        if (isVisible()) {
            hashModel.addDataInstance(currentProgram, data, TaskMonitor.DUMMY);
        }
    }

    void remove(Address addr) {
        if (isVisible()) {
            hashModel.removeDataInstanceAt(addr);
        }
    }

    void remove(Address start, Address end) {
        if (isVisible()) {
            long count = end.subtract(start);
            for (long offset = 0; offset < count; offset++) {
                hashModel.removeDataInstanceAt(start.add(offset));
            }
        }
    }

    void reload() {
        if (isVisible()) {
            hashModel.reload();
        }
    }

    public GhidraTable getTable() {
        return table;
    }

    public HashViewerTableModel getModel() {
        return hashModel;
    }

    private void doShowProgramLocation(ProgramLocation loc) {
        ProgramLocation realLoc = hashModel.findEquivProgramLocation(loc);
        if (realLoc != null) {
            int rowIndex = hashModel.getViewIndex(realLoc);
            if (rowIndex >= 0) {
                table.selectRow(rowIndex);
                table.scrollToSelectedRow();
            }
            else {
                getTool().setStatusInfo(
                    "Function at " + realLoc.getAddress() + " is filtered out of table view", false);
            }
        }
    }

    public void showProgramLocation(ProgramLocation loc) {
        if (loc == null) {
            return;
        }

        if (!hashModel.isBusy()) {
            doShowProgramLocation(loc);
        }
        else {
            delayedShowProgramLocation.set(loc);
        }
    }

    public int getSelectedRowCount() {
        return table.getSelectedRowCount();
    }

    public Data getSelectedData() {
        int selectedRow = table.getSelectedRow();
        if (selectedRow < 0) {
            return null;
        }
        ProgramLocation location = hashModel.getRowObject(selectedRow);
        return DataUtilities.getDataAtLocation(location);
    }

    public List<Data> getSelectedDataList(Predicate<Data> filter) {
        List<Data> list = new ArrayList<>();
        int[] selectedRows = table.getSelectedRows();
        for (int row : selectedRows) {
            ProgramLocation location = hashModel.getRowObject(row);
            Data data = DataUtilities.getDataAtLocation(location);
            if (passesFilter(data, filter)) {
                list.add(data);
            }
        }
        return list;
    }

    public List<ProgramLocation> getSelectedDataLocationList(Predicate<Data> filter) {
        List<ProgramLocation> result = new ArrayList<>();
        int[] selectedRows = table.getSelectedRows();
        for (int row : selectedRows) {
            ProgramLocation location = hashModel.getRowObject(row);
            Data data = DataUtilities.getDataAtLocation(location);
            if (passesFilter(data, filter)) {
                result.add(location);
            }
        }
        return result;
    }

    private boolean passesFilter(Data data, Predicate<Data> filter) {
        if (data == null) {
            return false;
        }
        if (filter == null) {
            return true;
        }
        return filter.test(data);
    }

    public Program getProgram() {
        return currentProgram;
    }

}
