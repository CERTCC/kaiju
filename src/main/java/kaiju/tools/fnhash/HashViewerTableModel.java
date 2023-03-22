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

// for supporting different Ghidra versions
import java.lang.reflect.*;
import java.util.HashMap;
import java.util.Map;

import db.NoTransactionException;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Swing;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.AbstractProgramLocationTableColumn;
import ghidra.util.table.field.AddressBasedLocation;
import ghidra.util.task.TaskMonitor;
import kaiju.common.KaijuPropertyManager;
import kaiju.hashing.FnHashSaveable;
import kaiju.util.HexUtils;

/**
 * Table model for the FnHash Viewer table.
 * <p>
 * This implementation keeps a local index of Address to row object (which are ProgramLocations)
 * so that DomainObjectChangedEvent events can be efficiently handled.
 */
public class HashViewerTableModel extends AddressBasedTableModel<ProgramLocation> {

    private Map<Address, ProgramLocation> rowsIndexedByAddress = new HashMap<>();

    /**
     * Columns defined by this table (useful for enum.ordinal()).
     * WARNING: Update GTableToYARA if this enum ever is updated!
     */
    public enum COLUMNS {
        ADDRESS_COL,
        EXACT_HASH_COL,
        PIC_HASH_COL,
        COMPOSITE_PIC_HASH_COL,
        MNEMONIC_HASH_COL,
        MNEMONIC_COUNT_HASH_COL,
        MNEMONIC_CATEGRORY_HASH_COL,
        MNEMONIC_CATEGORY_COUNT_HASH_COL,
        NUM_BASIC_BLOCKS_COL,
        NUM_BASIC_BLOCKS_IN_CFG_COL,
        NUM_INSTRUCTIONS_COL,
        NUM_BYTES_COL,
        EXACT_BYTES_COL,
        PIC_BYTES_COL
    }

    HashViewerTableModel(PluginTool tool) {
        super("FnHash Viewer Table", tool, null, null);
    }

    @Override
    protected TableColumnDescriptor<ProgramLocation> createTableColumnDescriptor() {
        TableColumnDescriptor<ProgramLocation> descriptor = new TableColumnDescriptor<>();

        // These columns need to match the COLUMNS enum indexes
        descriptor.addVisibleColumn(new DataLocationColumn(), 1, true);
        descriptor.addVisibleColumn(new ExactHashColumn());
        descriptor.addVisibleColumn(new PICHashColumn());
        descriptor.addHiddenColumn(new MnemonicHashColumn());
        descriptor.addHiddenColumn(new MnemonicCountHashColumn());
        descriptor.addHiddenColumn(new MnemonicCategoryHashColumn());
        descriptor.addHiddenColumn(new MnemonicCategoryCountHashColumn());
        descriptor.addHiddenColumn(new NumBasicBlocksColumn());
        descriptor.addHiddenColumn(new NumBasicBlocksInCfgColumn());
        descriptor.addHiddenColumn(new NumInstructionsColumn());
        descriptor.addVisibleColumn(new NumBytesColumn());
        descriptor.addHiddenColumn(new ExactBytesColumn());
        descriptor.addHiddenColumn(new PICBytesColumn());

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
            monitor.checkCanceled();
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
    
    private static class ExactHashColumn
            extends AbstractProgramLocationTableColumn<ProgramLocation, String> {

        @Override
        public String getColumnName() {
            return "Exact Hash";
        }

        @Override
        public String getValue(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
                
            ObjectPropertyMap fnhashmap = null;
            
            // TODO: this needs a better error handling procedure
            try {
                fnhashmap = KaijuPropertyManager.getOrCreateObjectPropertyMap(program, "FnHash", FnHashSaveable.class);
            } catch (NoTransactionException nte) {
                return "";
            }
            
            if (fnhashmap != null) {
            
                Class<?> c = null;
                try {
                    c = Class.forName("ghidra.program.model.util.ObjectPropertyMap");
                } catch (ClassNotFoundException e) {
                    return "";
                }

                FnHashSaveable prop = null;
                try
                {
                    // the get() function was introduced in Ghidra 10.2
                    fnhashmap.getClass().getDeclaredMethod("get", Address.class);
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("get", Address.class).invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e) {
                        return "";
                    }
                } catch(NoSuchMethodException e) {
                    // before Ghidra 10.2, it was getObject()
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("getObject").invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e2) {
                        return "";
                    }
                }
                
                //FnHashSaveable prop = (FnHashSaveable) fnhashmap.getObject(rowObject.getAddress());
                if (prop == null) {
                    // TODO: hash wasn't computed for this function, why?
                    // HINT: it seems like the ones missing hashes are largely external functions,
                    // do we want to do anything special with them in GUI, etc?
                    return "";
                } else {
                    return prop.getExactHash();
                }
            } else {
                // TODO: fnhashmap doesn't exist, can we auto run the Analyzer here?
                return "";
            }
        }

        @Override
        public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) {
            return rowObject;
        }
        
    }

    private static class PICHashColumn
            extends AbstractProgramLocationTableColumn<ProgramLocation, String> {

        @Override
        public String getColumnName() {
            return "PIC Hash";
        }

        @Override
        public String getValue(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
                
            ObjectPropertyMap fnhashmap = null;
            
            // TODO: this needs a better error handling procedure
            try {
                fnhashmap = KaijuPropertyManager.getOrCreateObjectPropertyMap(program, "FnHash", FnHashSaveable.class);
            } catch (NoTransactionException nte) {
                return "";
            }
            
            if (fnhashmap != null) {
            
                Class<?> c = null;
                try {
                    c = Class.forName("ghidra.program.model.util.ObjectPropertyMap");
                } catch (ClassNotFoundException e) {
                    return "";
                }

                FnHashSaveable prop = null;
                try
                {
                    // the get() function was introduced in Ghidra 10.2
                    fnhashmap.getClass().getDeclaredMethod("get", Address.class);
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("get", Address.class).invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e) {
                        return "";
                    }
                } catch(NoSuchMethodException e) {
                    // before Ghidra 10.2, it was getObject()
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("getObject").invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e2) {
                        return "";
                    }
                }
                
                //FnHashSaveable prop = (FnHashSaveable) fnhashmap.getObject(rowObject.getAddress());
                if (prop == null) {
                    // TODO: hash wasn't computed for this function, why?
                    return "";
                } else {
                    return prop.getPICHash();
                }
            } else {
                // TODO: fnhashmap doesn't exist, can we auto run the Analyzer here?
                return "";
            }
        }

        @Override
        public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) {
            return rowObject;
        }
        
    }
    
    private static class MnemonicHashColumn
            extends AbstractProgramLocationTableColumn<ProgramLocation, String> {

        @Override
        public String getColumnName() {
            return "Mnemonic Hash";
        }

        @Override
        public String getValue(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
                
            ObjectPropertyMap fnhashmap = null;
            
            // TODO: this needs a better error handling procedure
            try {
                fnhashmap = KaijuPropertyManager.getOrCreateObjectPropertyMap(program, "FnHash", FnHashSaveable.class);
            } catch (NoTransactionException nte) {
                return "";
            }
            
            if (fnhashmap != null) {
                
                Class<?> c = null;
                try {
                    c = Class.forName("ghidra.program.model.util.ObjectPropertyMap");
                } catch (ClassNotFoundException e) {
                    return "";
                }

                FnHashSaveable prop = null;
                try
                {
                    // the get() function was introduced in Ghidra 10.2
                    fnhashmap.getClass().getDeclaredMethod("get", Address.class);
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("get", Address.class).invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e) {
                        return "";
                    }
                } catch(NoSuchMethodException e) {
                    // before Ghidra 10.2, it was getObject()
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("getObject").invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e2) {
                        return "";
                    }
                }
                
                //FnHashSaveable prop = (FnHashSaveable) fnhashmap.getObject(rowObject.getAddress());
                if (prop == null) {
                    // TODO: hash wasn't computed for this function, why?
                    return "";
                } else {
                    return prop.getMnemonicHash();
                }
            } else {
                // TODO: fnhashmap doesn't exist, can we auto run the Analyzer here?
                return "";
            }
        }

        @Override
        public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) {
            return rowObject;
        }
        
    }
    
    private static class MnemonicCountHashColumn
            extends AbstractProgramLocationTableColumn<ProgramLocation, String> {

        @Override
        public String getColumnName() {
            return "Mnemonic Count Hash";
        }

        @Override
        public String getValue(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
                
            ObjectPropertyMap fnhashmap = null;
            
            // TODO: this needs a better error handling procedure
            try {
                fnhashmap = KaijuPropertyManager.getOrCreateObjectPropertyMap(program, "FnHash", FnHashSaveable.class);
            } catch (NoTransactionException nte) {
                return "";
            }
            
            if (fnhashmap != null) {
                
                Class<?> c = null;
                try {
                    c = Class.forName("ghidra.program.model.util.ObjectPropertyMap");
                } catch (ClassNotFoundException e) {
                    return "";
                }

                FnHashSaveable prop = null;
                try
                {
                    // the get() function was introduced in Ghidra 10.2
                    fnhashmap.getClass().getDeclaredMethod("get", Address.class);
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("get", Address.class).invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e) {
                        return "";
                    }
                } catch(NoSuchMethodException e) {
                    // before Ghidra 10.2, it was getObject()
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("getObject").invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e2) {
                        return "";
                    }
                }
                
                //FnHashSaveable prop = (FnHashSaveable) fnhashmap.getObject(rowObject.getAddress());
                if (prop == null) {
                    // TODO: hash wasn't computed for this function, why?
                    return "";
                } else {
                    return prop.getMnemonicCountHash();
                }
            } else {
                // TODO: fnhashmap doesn't exist, can we auto run the Analyzer here?
                return "";
            }
        }

        @Override
        public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) {
            return rowObject;
        }
        
    }
    
    private static class MnemonicCategoryHashColumn
            extends AbstractProgramLocationTableColumn<ProgramLocation, String> {

        @Override
        public String getColumnName() {
            return "Mnemonic Category Hash";
        }

        @Override
        public String getValue(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
                
            ObjectPropertyMap fnhashmap = null;
            
            // TODO: this needs a better error handling procedure
            try {
                fnhashmap = KaijuPropertyManager.getOrCreateObjectPropertyMap(program, "FnHash", FnHashSaveable.class);
            } catch (NoTransactionException nte) {
                return "";
            }
            
            if (fnhashmap != null) {
                
                Class<?> c = null;
                try {
                    c = Class.forName("ghidra.program.model.util.ObjectPropertyMap");
                } catch (ClassNotFoundException e) {
                    return "";
                }

                FnHashSaveable prop = null;
                try
                {
                    // the get() function was introduced in Ghidra 10.2
                    fnhashmap.getClass().getDeclaredMethod("get", Address.class);
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("get", Address.class).invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e) {
                        return "";
                    }
                } catch(NoSuchMethodException e) {
                    // before Ghidra 10.2, it was getObject()
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("getObject").invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e2) {
                        return "";
                    }
                }
                
                //FnHashSaveable prop = (FnHashSaveable) fnhashmap.getObject(rowObject.getAddress());
                if (prop == null) {
                    // TODO: hash wasn't computed for this function, why?
                    return "";
                } else {
                    return prop.getMnemonicCategoryHash();
                }
            } else {
                // TODO: fnhashmap doesn't exist, can we auto run the Analyzer here?
                return "";
            }
        }

        @Override
        public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) {
            return rowObject;
        }
        
    }
    
    private static class MnemonicCategoryCountHashColumn
            extends AbstractProgramLocationTableColumn<ProgramLocation, String> {

        @Override
        public String getColumnName() {
            return "Mnemonic Category Count Hash";
        }

        @Override
        public String getValue(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
                
            ObjectPropertyMap fnhashmap = null;
            
            // TODO: this needs a better error handling procedure
            try {
                fnhashmap = KaijuPropertyManager.getOrCreateObjectPropertyMap(program, "FnHash", FnHashSaveable.class);
            } catch (NoTransactionException nte) {
                return "";
            }
            
            if (fnhashmap != null) {
                
                Class<?> c = null;
                try {
                    c = Class.forName("ghidra.program.model.util.ObjectPropertyMap");
                } catch (ClassNotFoundException e) {
                    return "";
                }

                FnHashSaveable prop = null;
                try
                {
                    // the get() function was introduced in Ghidra 10.2
                    fnhashmap.getClass().getDeclaredMethod("get", Address.class);
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("get", Address.class).invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e) {
                        return "";
                    }
                } catch(NoSuchMethodException e) {
                    // before Ghidra 10.2, it was getObject()
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("getObject").invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e2) {
                        return "";
                    }
                }
                
                //FnHashSaveable prop = (FnHashSaveable) fnhashmap.getObject(rowObject.getAddress());
                if (prop == null) {
                    // TODO: hash wasn't computed for this function, why?
                    return "";
                } else {
                    return prop.getMnemonicCategoryCountHash();
                }
            } else {
                // TODO: fnhashmap doesn't exist, can we auto run the Analyzer here?
                return "";
            }
        }

        @Override
        public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) {
            return rowObject;
        }
        
    }
    
    private static class NumBasicBlocksColumn
            extends AbstractProgramLocationTableColumn<ProgramLocation, Integer> {

        @Override
        public String getColumnName() {
            return "Basic Block Count";
        }

        @Override
        public Integer getValue(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
                
            ObjectPropertyMap fnhashmap = null;
            
            // TODO: this needs a better error handling procedure
            try {
                fnhashmap = KaijuPropertyManager.getOrCreateObjectPropertyMap(program, "FnHash", FnHashSaveable.class);
            } catch (NoTransactionException nte) {
                return -1;
            }
            
            if (fnhashmap != null) {
                
                Class<?> c = null;
                try {
                    c = Class.forName("ghidra.program.model.util.ObjectPropertyMap");
                } catch (ClassNotFoundException e) {
                    return -1;
                }

                FnHashSaveable prop = null;
                try
                {
                    // the get() function was introduced in Ghidra 10.2
                    fnhashmap.getClass().getDeclaredMethod("get", Address.class);
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("get", Address.class).invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e) {
                        return -1;
                    }
                } catch(NoSuchMethodException e) {
                    // before Ghidra 10.2, it was getObject()
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("getObject").invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e2) {
                        return -1;
                    }
                }
                
                //FnHashSaveable prop = (FnHashSaveable) fnhashmap.getObject(rowObject.getAddress());
                if (prop == null) {
                    // TODO: hash wasn't computed for this function, why?
                    return -1;
                } else {
                    return prop.getNumBasicBlocks();
                }
            } else {
                // TODO: fnhashmap doesn't exist, can we auto run the Analyzer here?
                return -1;
            }
        }

        @Override
        public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) {
            return rowObject;
        }
        
    }
    
    private static class NumBasicBlocksInCfgColumn
            extends AbstractProgramLocationTableColumn<ProgramLocation, Integer> {

        @Override
        public String getColumnName() {
            return "Basic Block CFG Count";
        }

        @Override
        public Integer getValue(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
                
            ObjectPropertyMap fnhashmap = null;
            
            // TODO: this needs a better error handling procedure
            try {
                fnhashmap = KaijuPropertyManager.getOrCreateObjectPropertyMap(program, "FnHash", FnHashSaveable.class);
            } catch (NoTransactionException nte) {
                return -1;
            }
            
            if (fnhashmap != null) {
            
                Class<?> c = null;
                try {
                    c = Class.forName("ghidra.program.model.util.ObjectPropertyMap");
                } catch (ClassNotFoundException e) {
                    return -1;
                }

                FnHashSaveable prop = null;
                try
                {
                    // the get() function was introduced in Ghidra 10.2
                    fnhashmap.getClass().getDeclaredMethod("get", Address.class);
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("get", Address.class).invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e) {
                        return -1;
                    }
                } catch(NoSuchMethodException e) {
                    // before Ghidra 10.2, it was getObject()
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("getObject").invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e2) {
                        return -1;
                    }
                }
                
                //FnHashSaveable prop = (FnHashSaveable) fnhashmap.getObject(rowObject.getAddress());
                if (prop == null) {
                    // TODO: hash wasn't computed for this function, why?
                    return -1;
                } else {
                    return prop.getNumBasicBlocksInCfg();
                }
            } else {
                // TODO: fnhashmap doesn't exist, can we auto run the Analyzer here?
                return -1;
            }
        }

        @Override
        public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) {
            return rowObject;
        }
        
    }
    
    private static class NumInstructionsColumn
            extends AbstractProgramLocationTableColumn<ProgramLocation, Integer> {

        @Override
        public String getColumnName() {
            return "Instruction Count";
        }

        @Override
        public Integer getValue(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
                
            ObjectPropertyMap fnhashmap = null;
            
            // TODO: this needs a better error handling procedure
            try {
                fnhashmap = KaijuPropertyManager.getOrCreateObjectPropertyMap(program, "FnHash", FnHashSaveable.class);
            } catch (NoTransactionException nte) {
                return -1;
            }
            
            if (fnhashmap != null) {
                
                Class<?> c = null;
                try {
                    c = Class.forName("ghidra.program.model.util.ObjectPropertyMap");
                } catch (ClassNotFoundException e) {
                    return -1;
                }

                FnHashSaveable prop = null;
                try
                {
                    // the get() function was introduced in Ghidra 10.2
                    fnhashmap.getClass().getDeclaredMethod("get", Address.class);
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("get", Address.class).invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e) {
                        return -1;
                    }
                } catch(NoSuchMethodException e) {
                    // before Ghidra 10.2, it was getObject()
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("getObject").invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e2) {
                        return -1;
                    }
                }
                
                //FnHashSaveable prop = (FnHashSaveable) fnhashmap.getObject(rowObject.getAddress());
                if (prop == null) {
                    // TODO: hash wasn't computed for this function, why?
                    return -1;
                } else {
                    return prop.getNumInstructions();
                }
            } else {
                // TODO: fnhashmap doesn't exist, can we auto run the Analyzer here?
                return -1;
            }
        }

        @Override
        public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) {
            return rowObject;
        }
        
    }
    
    private static class NumBytesColumn
            extends AbstractProgramLocationTableColumn<ProgramLocation, Integer> {

        @Override
        public String getColumnName() {
            return "Bytes Count";
        }

        @Override
        public Integer getValue(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
                
            ObjectPropertyMap fnhashmap = null;
            
            // TODO: this needs a better error handling procedure
            try {
                fnhashmap = KaijuPropertyManager.getOrCreateObjectPropertyMap(program, "FnHash", FnHashSaveable.class);
            } catch (NoTransactionException nte) {
                return null;
            }
            
            if (fnhashmap != null) {
                
                Class<?> c = null;
                try {
                    c = Class.forName("ghidra.program.model.util.ObjectPropertyMap");
                } catch (ClassNotFoundException e) {
                    return null;
                }

                FnHashSaveable prop = null;
                try
                {
                    // the get() function was introduced in Ghidra 10.2
                    fnhashmap.getClass().getDeclaredMethod("get", Address.class);
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("get", Address.class).invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e) {
                        return null;
                    }
                } catch(NoSuchMethodException e) {
                    // before Ghidra 10.2, it was getObject()
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("getObject").invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e2) {
                        return null;
                    }
                }
                
                //FnHashSaveable prop = (FnHashSaveable) fnhashmap.getObject(rowObject.getAddress());
                if (prop == null) {
                    // TODO: hash wasn't computed for this function, why?
                    return null;
                } else {
                    return prop.getNumBytes();
                }
            } else {
                // TODO: fnhashmap doesn't exist, can we auto run the Analyzer here?
                return null;
            }
        }

        @Override
        public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) {
            return rowObject;
        }
        
    }

    private static class ExactBytesColumn
            extends AbstractProgramLocationTableColumn<ProgramLocation, String> {

        @Override
        public String getColumnName() {
            return "Exact Bytes";
        }

        @Override
        public String getValue(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
                
            ObjectPropertyMap fnhashmap = null;
            
            // TODO: this needs a better error handling procedure
            try {
                fnhashmap = KaijuPropertyManager.getOrCreateObjectPropertyMap(program, "FnHash", FnHashSaveable.class);
            } catch (NoTransactionException nte) {
                return "";
            }
            
            if (fnhashmap != null) {
                
                Class<?> c = null;
                try {
                    c = Class.forName("ghidra.program.model.util.ObjectPropertyMap");
                } catch (ClassNotFoundException e) {
                    return "";
                }

                FnHashSaveable prop = null;
                try
                {
                    // the get() function was introduced in Ghidra 10.2
                    fnhashmap.getClass().getDeclaredMethod("get", Address.class);
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("get", Address.class).invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e) {
                        return "";
                    }
                } catch(NoSuchMethodException e) {
                    // before Ghidra 10.2, it was getObject()
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("getObject").invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e2) {
                        return "";
                    }
                }
                
                //FnHashSaveable prop = (FnHashSaveable) fnhashmap.getObject(rowObject.getAddress());
                if (prop == null) {
                    // TODO: hash wasn't computed for this function, why?
                    return null;
                } else {
                    return HexUtils.byteArrayToHexString(prop.getExactBytes(), " ");
                }
            } else {
                // TODO: fnhashmap doesn't exist, can we auto run the Analyzer here?
                return null;
            }
        }

        @Override
        public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) {
            return rowObject;
        }
        
    }
    
    private static class PICBytesColumn
            extends AbstractProgramLocationTableColumn<ProgramLocation, String> {

        @Override
        public String getColumnName() {
            return "PIC Bytes";
        }

        @Override
        public String getValue(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
                
            ObjectPropertyMap fnhashmap = null;
            
            // TODO: this needs a better error handling procedure
            try {
                fnhashmap = KaijuPropertyManager.getOrCreateObjectPropertyMap(program, "FnHash", FnHashSaveable.class);
            } catch (NoTransactionException nte) {
                return "";
            }
            
            if (fnhashmap != null) {
                
                Class<?> c = null;
                try {
                    c = Class.forName("ghidra.program.model.util.ObjectPropertyMap");
                } catch (ClassNotFoundException e) {
                    return "";
                }

                FnHashSaveable prop = null;
                try
                {
                    // the get() function was introduced in Ghidra 10.2
                    fnhashmap.getClass().getDeclaredMethod("get", Address.class);
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("get", Address.class).invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e) {
                        return "";
                    }
                } catch(NoSuchMethodException e) {
                    // before Ghidra 10.2, it was getObject()
                    try {
                        prop = (FnHashSaveable) fnhashmap.getClass().getDeclaredMethod("getObject").invoke(fnhashmap, rowObject.getAddress());
                    } catch (Exception e2) {
                        return "";
                    }
                }
                
                //FnHashSaveable prop = (FnHashSaveable) fnhashmap.getObject(rowObject.getAddress());
                if (prop == null) {
                    // TODO: hash wasn't computed for this function, why?
                    return null;
                } else {
                    return HexUtils.byteArrayToHexString(prop.getPICBytes(), " ");
                }
            } else {
                // TODO: fnhashmap doesn't exist, can we auto run the Analyzer here?
                return null;
            }
        }

        @Override
        public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
                Program program, ServiceProvider serviceProvider) {
            return rowObject;
        }
        
    }

}
