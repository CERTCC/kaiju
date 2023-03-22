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
package kaiju.tools.disasm;

import java.util.HashSet;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.task.gui.GProgressBar;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import kaiju.common.KaijuLogger;
import kaiju.tools.disasm.DisasmImprover;
import kaiju.tools.disasm.GhidraTypeUtilities;
import kaiju.util.Pair;

 /**
 * A Ghidra analyzer pass that improves function partitioning in a program.
 * Previously known as "MakeAlignment".
 * Documentation is at:
 * docs/api/ghidra/app/services/AbstractAnalyzer.html
 */
public class DisasmImprovementsAnalyzer extends AbstractAnalyzer implements KaijuLogger {
    public static final boolean doingdebug = true;
    
    private final static String NAME = "Kaiju Disassembly Improvements";
    private final static String DESCRIPTION = "Improved program partitioning and disassembly algorithm.";
    protected static final String OPTION_NAME_MA_FILE = "Run Kaiju Disassembly Improvements";
    
    public DisasmImprovementsAnalyzer() {

        super(NAME, DESCRIPTION, AnalyzerType.DATA_ANALYZER);

        // Data type propagation is the latest analysis phase. This will run after
        // that because it needs to update functions and data types, see:
        // docs/api/ghidra/app/services/AnalysisPriority.html
        setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after());

        // Analysis is enabled by default,
        setDefaultEnablement(true);

        setSupportsOneTimeAnalysis();
    }

    private DataTypeManager dataTypeManager;
    private DataType alignmentType;
    private DataType stringType;
    private Listing listing;
    private Memory memory;
    private AddressSetView allAddresses;
    private AddressSetView undefinedAddresses;
    private TaskMonitor monitor;
    private Program currentProgram;
    private DisasmImprover improver;

    // Records of what we've done.
    private AddressSet alignmentAddresses;
    private AddressSet codeAddresses;
    private AddressSet stringAddresses;
    private HashSet<Address> skippedAddresses;

    /** 
     * This analyzer is selected by default to run in the Auto-Analyze feature.
     */
    @Override
    public boolean getDefaultEnablement(final Program program) {

        return true;
    }

    /** 
     * Checks if the program is X86 architecture before running this analyzer.
     * This tool makes some assumptions that are only valid for X86,
     * therefore we do not apply it to any program that is not this architecture.
     */
    @Override
    public boolean canAnalyze(final Program program) {

        // Only analyze 32-bit X86 programs. OOAnalyzer can handle nothing else.
        // TODO: is this restriction an unnecessary holdover from pharos?
        final Processor processor = program.getLanguage().getProcessor();
        if (program.getLanguage().getDefaultSpace().getSize() != 32) {
            return false;
        }
        return processor.equals(Processor.findOrPossiblyCreateProcessor("x86"));
    }

    @Override
    public boolean added(final Program program, final AddressSetView set, final TaskMonitor monitor,
            final MessageLog log) throws CancelledException {


        debug(this, "Running the Disassembly Improvements analyzer!");
        this.currentProgram = program;
        this.monitor = monitor;

        if (currentProgram == null) {
            debug(this, "Failed to find currentProgram!");
            System.exit(-1);
        }

        debug(this, currentProgram.toString());

        // TODO:
        // I should do something here to ensure that the program being
        // analyzed is for the X86 architecture, since many of my
        // heuristics are really X86 specific.

        listing = currentProgram.getListing();
        memory = currentProgram.getMemory();

        // Find the "Alignment" type in the builtin data type manager.
        dataTypeManager = BuiltInDataTypeManager.getDataTypeManager();
        alignmentType = GhidraTypeUtilities.findGhidraType("Alignment");
        if (alignmentType == null) {
            debug(this, "Unable to find builtin alignment type! Aborting.");
            return false;
        }
        // Find the "string" type in the builtin data type manager.
        stringType = GhidraTypeUtilities.findGhidraType("string");
        if (stringType == null) {
            debug(this, "Unable to find builtin string type! Aborting.");
            return false;
        }
        
        improver = new DisasmImprover(currentProgram, monitor);
        // TODO: should we check arch here or inside the improver?
        // can we share code with the canAnalyze() function?
        try {
            final Processor processor = currentProgram.getLanguage().getProcessor();
            if (processor.equals(Processor.findOrPossiblyCreateProcessor("x86"))) {
                improver.setImproverStrategy("x86");
            }
        } catch (InvalidImproverStrategyException e) {
            // TODO: need to safely abort if we couldn't set an exception
        }

        // currentProgram getminAddress() and getMaxAddress()?
        allAddresses = memory.getAllInitializedAddressSet();

        alignmentAddresses = new AddressSet();
        codeAddresses = new AddressSet();
        stringAddresses = new AddressSet();
        skippedAddresses = new HashSet<Address>();

        // loop over the undefined addresses until either they are identified
        // or there's no heuristics left to run.
        // CancelledListener cancelledListener
        GProgressBar progress = new GProgressBar​(null, true, true, true, 12);
        progress.setMessage("Analyzing gaps...");
        progress.initialize(0);
        
        long num_addrs_undefined = 0;
        undefinedAddresses = this.listing.getUndefinedRanges(allAddresses, false, monitor);
        for (final AddressRange range : undefinedAddresses) {
            num_addrs_undefined += range.getLength();
        }
        progress.setMaximum(num_addrs_undefined);
        
        while (true) {
            long changed = 0;
            debug(this, "Analyzing gaps...");

            for (final AddressRange range : undefinedAddresses) {
                //long range_change = improver.analyzeGap(range);
                Pair<AddressRange, Integer> range_pair = improver.analyzeGap(range);
                long range_change = range_pair.second;
                progress.incrementProgress(range_change);
                changed += range_change;
            }
            if (changed == 0)
                break;
            // set up for next loop
            undefinedAddresses = this.listing.getUndefinedRanges(allAddresses, false, monitor);
        }

        // Report what we've done (in "ranges" where we can)...
        debug(this, "Took no action at the following addresses: " + skippedAddresses);
        debug(this, "Made alignment in the following ranges: " + alignmentAddresses);
        debug(this, "Made code in the following ranges: " + codeAddresses);
        debug(this, "Speculatively made strings in the following ranges: " + stringAddresses);

        return false;
    }
    
    // Outstanding bugs in ooex7:
    // 0x0041e4a1 -> 0x004302a0 (but latter was already made into alignment. :-()
    // Lots of unmade functions around 0x417b50 - 0x417cb8
    // Problems with exception handler data structures not made correctly around 0x412a1e
    // Next on todo list is to handle the very-large-gap bug I just fixed in ROSE.


}
