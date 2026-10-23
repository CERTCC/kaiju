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

import java.util.HashMap;
import java.util.Map;

import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Swing;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.AbstractProgramLocationTableColumn;
import ghidra.util.table.field.AddressBasedLocation;
import ghidra.util.task.TaskMonitor;

/**
 * Table model for the Fn Xrefs Viewer table.
 * <p>
 * This implementation keeps a local index of Address to row object (which are ProgramLocations)
 * so that DomainObjectChangedEvent events can be efficiently handled.
 */
public class FnXrefViewerTableModel extends AddressBasedTableModel<ProgramLocation> {

    private Map<Address, ProgramLocation> rowsIndexedByAddress = new HashMap<>();

    /**
     * Columns defined by this table (useful for enum.ordinal()).
     * WARNING: Update GTableToYARA if this enum ever is updated!
     */
    public enum COLUMNS {
        ADDRESS_COL,
        DATA_XREF_COUNT_COL,
        CODE_XREF_COUNT_COL
    }

    FnXrefViewerTableModel(PluginTool tool) {
        super("FnXref Viewer Table", tool, null, null);
    }

    @Override
    protected TableColumnDescriptor<ProgramLocation> createTableColumnDescriptor() {
        TableColumnDescriptor<ProgramLocation> descriptor = new TableColumnDescriptor<>();

        // These columns need to match the COLUMNS enum indexes
        descriptor.addVisibleColumn(new DataLocationColumn(), 1, true);
        descriptor.addVisibleColumn(new CodeXrefCountColumn());
        descriptor.addVisibleColumn(new DataXrefCountColumn());

        return descriptor;
    }

    @Override
    protected void doLoad(Accumulator<ProgramLocation> accumulator, TaskMonitor monitor)
            throws CancelledException {
        rowsIndexedByAddress.clear();

        Program localProgram = getProgram();
        if (localProgram == null) {
            return;
        }

        Listing listing = localProgram.getListing();
            
        monitor.setCancelEnabled(true);
        monitor.initialize(listing.getNumDefinedData());
        Swing.allowSwingToProcessEvents();
        for (Function funcInstance : localProgram.getFunctionManager().getFunctions(true)) {
            accumulator.add(createIndexedFunctionInstanceLocation(localProgram, funcInstance));
            monitor.checkCancelled();
            monitor.incrementProgress(1);
        }
    }

    private ProgramLocation createIndexedFunctionInstanceLocation(Program localProgram, Function data) {
        ProgramLocation pl = new ProgramLocation(localProgram, data.getEntryPoint(),
            null, null, 0, 0, 0);
        rowsIndexedByAddress.put(data.getEntryPoint(), pl);
        return pl;
    }

    public void removeDataInstanceAt(Address addr) {
        ProgramLocation progLoc = rowsIndexedByAddress.get(addr);
        if (progLoc != null) {
            removeObject(progLoc);
        }
    }

    public ProgramLocation findEquivProgramLocation(ProgramLocation pl) {
        return (pl != null) ? rowsIndexedByAddress.get(pl.getAddress()) : null;
    }

    public void addDataInstance(Program localProgram, Function data, TaskMonitor monitor) {
        addObject(createIndexedFunctionInstanceLocation(localProgram, data));
    }
    // localProgram.getFunctionManager().getFunctions(true)
    //     public void addDataInstance(Program localProgram, Data data, TaskMonitor monitor) {
    //         for (Data stringInstance : DefinedDataIterator.definedStrings(data)) {
    //             addObject(createIndexedFunctionInstanceLocation(localProgram, stringInstance));
    //         }
    //     }

    @Override
    public ProgramSelection getProgramSelection(int[] rows) {
        AddressSet set = new AddressSet();
        for (int element : rows) {
            ProgramLocation progLoc = filteredData.get(element);
            set.add(progLoc.getAddress());
        }
        return new ProgramSelection(set);
    }

    public void reload(Program newProgram) {
        setProgram(newProgram);
        reload();
    }

    @Override
    public Address getAddress(int row) {
        return getRowObject(row).getAddress();
    }

//==================================================================================================
// Inner Classes
//==================================================================================================

    private static class DataLocationColumn
            extends AbstractProgramLocationTableColumn<ProgramLocation, AddressBasedLocation> {

        @Override
        public String getColumnName() {
            return "Location";
        }

        @Override
        public AddressBasedLocation getValue(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
            return new AddressBasedLocation(rowObject.getProgram(), rowObject.getAddress());

        }

        @Override
        public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) {
            return rowObject;
        }

    }
    
    private static class CodeXrefCountColumn
            extends AbstractProgramLocationTableColumn<ProgramLocation, String> {

        @Override
        public String getColumnName() {
            return "Code X-Refs Count";
        }

        @Override
        public String getValue(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
                
            // function entry point address
            Address fnEntryAddress = rowObject.getAddress();
            
            ReferenceManager refman = program.getReferenceManager();
            ReferenceIterator refiter = refman.getReferencesTo(fnEntryAddress);
            //refman.getReferenceCountTo(fnEntryAddress);
            
            int codeRefCnt = 0;
            for (Reference xref : refiter) {
                if (!xref.getReferenceType().isData()) {
                    codeRefCnt++;
                }
            }
            
            return String.valueOf(codeRefCnt);
            
        }

        @Override
        public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) {
            return rowObject;
        }
        
    }
    
    private static class DataXrefCountColumn
            extends AbstractProgramLocationTableColumn<ProgramLocation, String> {

        @Override
        public String getColumnName() {
            return "Data X-Refs Count";
        }

        @Override
        public String getValue(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
                
            // function entry point address
            Address fnEntryAddress = rowObject.getAddress();
            
            ReferenceManager refman = program.getReferenceManager();
            ReferenceIterator refiter = refman.getReferencesTo(fnEntryAddress);
            
            int dataRefCnt = 0;
            for (Reference xref : refiter) {
                if (xref.getReferenceType().isData()) {
                    dataRefCnt++;
                }
            }
            
            return String.valueOf(dataRefCnt);
            
        }

        @Override
        public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) {
            return rowObject;
        }
        
    }
    
}
