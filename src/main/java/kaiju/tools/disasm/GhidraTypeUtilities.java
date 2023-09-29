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

import ghidra.program.model.address.Address;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;

/**
 * A static class with utility functions for locating Ghidra
 * data types as subclasses of DataType.
 */
public class GhidraTypeUtilities {

    public enum BlockType {
        CODE, DATA, ALIGNMENT, OTHER
    }
    
    public static DataType findGhidraType(final String name) {
        DataTypeManager dataTypeManager = BuiltInDataTypeManager.getDataTypeManager();
        DataType dt = dataTypeManager.getDataType(CategoryPath.ROOT, name);
        if (dt == null) {
            dt = dataTypeManager.getDataType(CategoryPath.ROOT, name);
            if (dt != null) {
                dt = dt.clone(dataTypeManager);
            }
        }
        return dt;
    }
    
    // Return the type of the block at address.
    public static BlockType getBlockType(final Listing listing, final Address address) {
        // Instruction insn = listing.getInstructionContaining(address);
        // if (insn != null)
        final CodeUnit cu = listing.getCodeUnitAt(address);
        // TODO: put cu in Optional container

        if (cu instanceof Instruction)
            return BlockType.CODE;
        // Data data = listing.getDataContaining(address);
        // if (data == null)
        if (cu instanceof Data) {
            final Data tempdata = (Data) cu;
            if (findGhidraType("Alignment") == tempdata.getDataType())
                return BlockType.ALIGNMENT;
            return BlockType.DATA;
        } else {
            return BlockType.OTHER;
        }

        // I'm a little surprised that an approach like this didn't work:
        // if (cu.hasProperty(CodeUnit.INSTRUCTION_PROPERTY)) return true;
        // CodeUnit properties are *not* set by the Framework code
        // Use /isinstance/ instead.
    }
    
    /* 
     * Note this gets the Minimum address in a CodeUnit that
     * may correspond to the Address OR _address_ if no CodeUnit is found;
     *  this should not be confused
     * with the getStartAddress() implemented for InstructionBlock:
     * https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/InstructionBlock.html#getStartAddress()
     */
    public static Address getStartAddress(final Listing listing, final Address address) {
        final CodeUnit cu = listing.getCodeUnitContaining(address);
        if (cu == null) {
            //debug(this, "No CodeUnit for " + address);
	    // Why is this passed back with no error?
	    // When do we want to keep processing when
	    // no CodeUnit is defined with _address_ as
	    // a member?
            return address;
        }
        return cu.getMinAddress();
    }
    
    public static Address getPreviousStartAddress(final Listing listing, final Address startAddress) {
        // We can't call getStartAddress here, because previous might not be a valid address.
        //final Address previous = startAddress.subtract(1);
        // from the documentation, it seems more correct to use previous() here than subtract():
        // https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/Address.html#previous()
        final Address previous = startAddress.previous();
        if (previous == null)
            // only happens when startAddress was 0x00 so previous returns null
            // TODO: is there something better to do here?
            return startAddress;
        // Further, getStartAddress will return previous if we failed to find anything.
        final Address previousStart = getStartAddress(listing, previous);
        if (previousStart == previous)
            return startAddress;
        // Otherwise, everything went smoothly.
        return previousStart;
    }
    
    // Return the type of the block immediately before address, skipping over one alignment
    // block if the immediately preceding block is an alignment block.
    public static BlockType getPreviousBlockType(final Listing listing, final Address address) {
        final Address previous = getPreviousStartAddress(listing, address);
        // TODO: what happens here if (previous == address)?
        final BlockType blockType = getBlockType(listing, previous);
        if (blockType == BlockType.ALIGNMENT) {
            final Address before_alignment = getPreviousStartAddress(listing, previous);
            return getBlockType(listing, before_alignment);
        }
        return blockType;
    }

}
