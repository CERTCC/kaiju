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
package kaiju.tools.disasm.impl;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;

import kaiju.tools.disasm.DisasmStrategy;
import kaiju.tools.disasm.GhidraTypeUtilities;
import kaiju.tools.disasm.GhidraTypeUtilities.BlockType;
import kaiju.util.Pair;

/**
 * Implementation of DisasmStrategy, specialized for x86 architecture.
 * Makes use of the "Strategy" design pattern:
 * https://howtodoinjava.com/design-patterns/behavioral/strategy-design-pattern/
 */
public class X86ImproverStrategy implements DisasmStrategy {

    private Program currentProgram;
    private TaskMonitor monitor;
    private Memory memory;
    private Listing listing;
    
    public X86ImproverStrategy(Program currentProgram, TaskMonitor monitor) {
        this.currentProgram = currentProgram;
        this.monitor = monitor;
        memory = currentProgram.getMemory();
        listing = currentProgram.getListing();
    }

    public Pair<AddressRange, Integer> analyzeGap(final AddressRange range) {
        // debug(this, "Undefined bytes at " + range);
        final Address minAddr = range.getMinAddress();
        
        // If we've already processed this address, don't try again.
        //if (skippedAddresses.contains(minAddr))
        //    return 0;
        
        // debug(this, "Analyzing gap: " + range + " with block type " + getBlockType(minAddr));

        // Upgrade the byte to an integer because types are signed in Java.
        int b = 0;
        try {
            b = memory.getByte(minAddr) & 0xFF;
        } catch (final MemoryAccessException e) {
            e.printStackTrace();
            //return 0;
            return new Pair<AddressRange, Integer>(range, 0);
        }
        
        // Address previous = minAddr.subtract(1);

        final BlockType previousBlockType = GhidraTypeUtilities.getPreviousBlockType(listing, minAddr);
        switch (previousBlockType) {
            case CODE:
                if (b == 0xCC) {
                    return makeAlignment(listing, minAddr, monitor);
                } else {
                    AddressSetView allAddresses = memory.getAllInitializedAddressSet();
                    return makeCode(currentProgram, listing, allAddresses, minAddr, monitor);
                }
            case DATA:
                if (b == 0x00)
                    return makeAlignment(listing, minAddr, monitor);
                break;
            case ALIGNMENT:
                debug(this, "I'm a little surprised to find alignment at " + minAddr);
                break;
            case OTHER:
                debug(this, "I'm a little surprised to find other at " + minAddr);
                break;
        }

        debug(this, "Skipping address: " + minAddr);
        //skippedAddresses.add(minAddr);
        //return 0;
        return new Pair<AddressRange, Integer>(range, 0);
    }

}
