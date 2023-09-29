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

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import kaiju.common.*;
import kaiju.util.Pair;

/**
 * An abstract interface to be used for specialized disassembly improvements
 * heuristics based on the architecture.
 * Each architecture gets its own implementation.
 * Makes use of the "Strategy" design pattern:
 * https://howtodoinjava.com/design-patterns/behavioral/strategy-design-pattern/
 */
public interface DisasmStrategy extends KaijuLogger {

    // returns array of categories in use by this architecture
    Pair<AddressRange, Integer> analyzeGap(final AddressRange range);
    
    /**
     * recognizes bytes at an address as alignment bytes.
     * this is a default implementation that shouldn't rely on
     * architecture, but can be overriden if needed for some reason.
     */
    default Pair<AddressRange, Integer> makeAlignment(Listing listing, final Address address, TaskMonitor monitor) {
        DataType alignmentType = GhidraTypeUtilities.findGhidraType("Alignment");
        try {
            Data alignData = listing.createData(address, alignmentType);
            final Address minAddr = alignData.getMinAddress();
            final Address maxAddr = alignData.getMaxAddress();
            final AddressRange range = new AddressRangeImpl(minAddr, maxAddr);
            debug(this, "Created alignment at: " + range);
            //alignmentAddresses.add(range);
            return new Pair<AddressRange, Integer>(range, 1);
        } catch (final CodeUnitInsertionException e) {
            // Don't report the exception, because we're going to just leave the address alone?
            debug(this, "Failed to make alignment at " + address);
            //skippedAddresses.add(address);
            try {
                final AddressRange range = new AddressRangeImpl(address, 1);
                return new Pair<AddressRange, Integer>(range, 0);
            } catch (AddressOverflowException aoe) {
                final AddressRange range = new AddressRangeImpl(address, address);
                return new Pair<AddressRange, Integer>(range, 0);
            }
        }
    }
    
    /**
     * recognizes bytes at a starting address as assembly code.
     * this relies on disassembling at the given starting address.
     * this is a default implementation that shouldn't rely on
     * architecture, but can be overriden if needed for some reason.
     */
    default Pair<AddressRange, Integer> makeCode(Program currentProgram, Listing listing, AddressSetView allAddresses, final Address address, TaskMonitor monitor) {
        // Making code at a previous gap might have converted this gap to code, so we need to
        // check again to see if this address range is still a gap...
        if (GhidraTypeUtilities.getBlockType(listing, address) == GhidraTypeUtilities.BlockType.CODE) {
            try {
                final AddressRange range = new AddressRangeImpl(address, 1);
                return new Pair<AddressRange, Integer>(range, 0);
            } catch (AddressOverflowException aoe) {
                final AddressRange range = new AddressRangeImpl(address, address);
                return new Pair<AddressRange, Integer>(range, 0);
            }
        }

        // debug(this, "Making code at " + address);
        AddressSetView undefinedAddresses = null;
        try {
            undefinedAddresses = listing.getUndefinedRanges(allAddresses, false, monitor);
        } catch (CancelledException e) {
            final AddressRange range = new AddressRangeImpl(address, address);
            return new Pair<AddressRange, Integer>(range, 0);
        }
        final DisassembleCommand disassembleCmd = new DisassembleCommand(address, undefinedAddresses, true);
        disassembleCmd.enableCodeAnalysis(true);
        disassembleCmd.applyTo(currentProgram, monitor);

        // I'm not sure what good the status message is really.
        final String statusMsg = disassembleCmd.getStatusMsg();
        if (statusMsg != null) {
            debug(this, "Disassembly status at " + address + " was: " + disassembleCmd.getStatusMsg());
            // TODO skippedAddresses.add(address);
            try {
                final AddressRange range = new AddressRangeImpl(address, 1);
                return new Pair<AddressRange, Integer>(range, 0);
            } catch (AddressOverflowException aoe) {
                final AddressRange range = new AddressRangeImpl(address, address);
                return new Pair<AddressRange, Integer>(range, 0);
            }
        }

        final AddressSet insnsCreated = disassembleCmd.getDisassembledAddressSet();
        debug(this, "Created instructions at: " + insnsCreated);
        // TODO codeAddresses.add(insnsCreated);
        try {
            final AddressRange range = new AddressRangeImpl(address, 1);
            return new Pair<AddressRange, Integer>(range, 1);
        } catch (AddressOverflowException aoe) {
            final AddressRange range = new AddressRangeImpl(address, address);
            return new Pair<AddressRange, Integer>(range, 1);
        }
    }
    
    default Pair<AddressRange, Integer> makeString(Program currentProgram, Listing listing, final Address address, TaskMonitor monitor) {
        DataType stringType = GhidraTypeUtilities.findGhidraType("string");
        Data stringData;
        try {
            stringData = listing.createData(address, stringType);
            final Address minAddr = stringData.getMinAddress();
            final Address maxAddr = stringData.getMaxAddress();
            final AddressRange range = new AddressRangeImpl(minAddr, maxAddr);
            debug(this, "Created string at: " + range);
            currentProgram.getBookmarkManager().setBookmark(address, "string", "KaijuDiasmImprovements", "created a string at this address");
            //stringAddresses.add(range);
            return new Pair<AddressRange, Integer>(range, 1);
        } catch (final CodeUnitInsertionException e) {
            // Don't report the exception, because we're going to just leave the address alone?
            debug(this, "Failed to make string at " + address);
            //skippedAddresses.add(address);
            final AddressRange range = new AddressRangeImpl(address, address);
            return new Pair<AddressRange, Integer>(range, 0);
        }
    }

}
