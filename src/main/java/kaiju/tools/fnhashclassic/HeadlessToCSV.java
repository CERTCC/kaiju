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
package kaiju.tools.fnhashclassic;

import java.io.File;
import java.io.FileWriter;
import java.util.StringJoiner;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import kaiju.hashing.FnHashSaveable;

public final class HeadlessToCSV {

    //public FileWriter csvFileWriter;
    

    public final static void writeCSV(File csvFile, Program currentProgram) throws Exception {

        FileWriter csvFileWriter = new FileWriter(csvFile,true);


        // create a new property map to store various function hashes
        PropertyMapManager mapmgr = currentProgram.getUsrPropertyManager();
        ObjectPropertyMap fnhashobjmap;
        // check if properties exist already, or if need to create
        fnhashobjmap = mapmgr.getObjectPropertyMap("__CERT_Kaiju_FnHash");

        AddressIterator addriter = fnhashobjmap.getPropertyIterator();

        while(addriter.hasNext()){
            Address fn_addr = addriter.next();
            
            FnHashSaveable fnhash = null;
            Class<?> c = null;
            try {
                c = Class.forName("ghidra.program.model.util.ObjectPropertyMap");
            } catch (ClassNotFoundException e) {
                //TODO
                return;
            }

            try
            {
                // the get() function was introduced in Ghidra 10.2
                c.getDeclaredMethod("get");
                try {
                    fnhash = (FnHashSaveable) c.getDeclaredMethod("get").invoke(fn_addr);
                } catch (Exception e) {
                    //TODO
                    return;
                }
            } catch(NoSuchMethodException e) {
                // before Ghidra 10.2, it was getObject()
                try {
                    fnhash = (FnHashSaveable) c.getDeclaredMethod("getObject").invoke(fn_addr);
                } catch (Exception e2) {
                    //TODO
                    return;
                }
            }
            //FnHashSaveable fnhash = (FnHashSaveable) fnhashobjmap.getObject(fn_addr);
            

            /*
             * Build CSV Line
             */
            // to match the pharos fn2hash to use fse.py, we need:
            // filemd5,fn_addr,num_basic_blocks,num_basic_blocks_in_cfg,num_instructions,num_bytes,exact_hash,pic_hash,composite_pic_hash,mnemonic_hash,mnemonic_count_hash,mnemonic_category_hash,mnemonic_category_counts_hash,mnemonic_count_string,mnemonic_category_count_string = line

            
            StringJoiner csv_fields_joined = new StringJoiner(",");
            
            csv_fields_joined.add(currentProgram.getExecutableMD5().toUpperCase()); // filemd5
            csv_fields_joined.add(fn_addr.toString().toUpperCase()); // fn_addr
            csv_fields_joined.add(Integer.toString(fnhash.getNumBasicBlocks())); // num_basic_blocks
            csv_fields_joined.add(Integer.toString(fnhash.getNumBasicBlocksInCfg())); // num_basic_blocks_in_cfg, TODO:check this, should this be different from num_basic_blocks?
            csv_fields_joined.add(Integer.toString(fnhash.getNumInstructions())); // num_instructions
            csv_fields_joined.add(Integer.toString(fnhash.getNumBytes())); // num_bytes
            csv_fields_joined.add(fnhash.getExactHash().toUpperCase()); // exact_hash
            csv_fields_joined.add(fnhash.getPICHash().toUpperCase()); // pic_hash
            csv_fields_joined.add(fnhash.getCompositePICHash().toUpperCase()); // composite_pic_hash
            csv_fields_joined.add(fnhash.getMnemonicHash().toUpperCase()); // mnemonic_hash
            csv_fields_joined.add(fnhash.getMnemonicCountHash().toUpperCase()); // mnemonic_count_hash
            csv_fields_joined.add(fnhash.getMnemonicCategoryHash().toUpperCase()); // mnemonic_category_hash
            csv_fields_joined.add(fnhash.getMnemonicCategoryCountHash().toUpperCase()); // mnemonic_category_counts_hash
            csv_fields_joined.add(fnhash.getMnemonicCountString().toUpperCase()); // mnemonic_count_string
            csv_fields_joined.add(fnhash.getMnemonicCategoryCountString().toUpperCase()); // mnemonic_category_count_string
        
            csvFileWriter.write(csv_fields_joined.toString()+"\n");
        }

        csvFileWriter.flush();
        csvFileWriter.close();
    }

}
