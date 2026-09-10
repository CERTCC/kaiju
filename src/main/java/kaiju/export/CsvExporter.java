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
package kaiju.export;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.*;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this exporter does.
 * Exporter documentation at:
 * https://ghidra.re/ghidra_docs/api/ghidra/app/util/exporter/Exporter.html
 * An exporter outputs a DomainObject as some type of file on file system,
 * standard formats are AsciiExporter and BinaryExporter.
 * NOTE: ProgramDB is a DomainObject that implements the Program interface.
 * So we should be able to export a Program to e.g. YARA by checking for
 * FnHashSaveable objects within the Program; null output if doesn't exist.
 */
public class CsvExporter extends Exporter {

    /**
     * Exporter constructor.
     */
    public CsvExporter() {

        // TODO: Name the exporter and associate a file extension with it
        // parameters are: exporter name String, file extension String, help location
        super("CERT FnHash CSV Exporter", "hash", null);
    }

    @Override
    public boolean canExportDomainObject(Class<? extends DomainObject> domainObjectClass) {
        return Program.class.isAssignableFrom(domainObjectClass);
    }

    @Override
    public boolean export(File file, DomainObject domainObj, AddressSetView addrSet,
            TaskMonitor monitor) throws ExporterException, IOException {

        // TODO: Perform the export, and return true if it succeeded
        
        // REGRESSION TESTING
        // form instruction and category counts as CSV string
        /*
        StringJoiner fn_insncnt_joined = new StringJoiner(";");
        StringJoiner fn_insncatcnt_joined = new StringJoiner(";");
        for (String key : fnu.fn_insncnt.keySet()) {
            fn_insncnt_joined.add(key.toLowerCase() + ":" + fnu.fn_insncnt.get(key)); 
        }
        
        for (String key : fnu.fn_insncatcnt.keySet()) {
            fn_insncatcnt_joined.add(key + ":" + fnu.fn_insncatcnt.get(key)); 
        }
        
        MessageDigest mcntmd5 = MessageDigest.getInstance("MD5");
        byte[] mcnthash = mcntmd5.digest(fn_insncnt_joined.toString().getBytes());
        
        MessageDigest mccntmd5 = MessageDigest.getInstance("MD5");
        byte[] mccnthash = mccntmd5.digest(fn_insncatcnt_joined.toString().getBytes());
        */
        
        // This is the format of the CSV file
        
        // REGRESSION TESTING NEEDED
        /* msg = fmd5.toUpperCase() + "," +
        fn_ep.toString().toUpperCase() + "," +
        fnu.code_units.size() + "," +
        fnu.num_insn + "," +
        fnu.num_bytes + "," +
        byteArrayToHexString(fnu.ehash,"") + "," +
        byteArrayToHexString(fnu.phash,"") + "," +
        fn_ebytes_string + "," +
    //    fn_pbytes_string;
        fn_pbytes_string + "," +
        fn_insncnt_joined.toString() + "," +
        fn_insncatcnt_joined.toString();

        */

        //StringJoiner csv_fields_joined = new StringJoiner(",");

        // TODO: parse the emitter to get canonical output;
        // hack the string together for now
        
        // to match the pharos fn2hash to use fse.py, we need:
        // filemd5,fn_addr,num_basic_blocks,num_basic_blocks_in_cfg,num_instructions,num_bytes,exact_hash,pic_hash,composite_pic_hash,mnemonic_hash,mnemonic_count_hash,mnemonic_category_hash,mnemonic_category_counts_hash,mnemonic_count_string,mnemonic_category_count_string = line

        /*
        csv_fields_joined.add(fmd5.toUpperCase()); // filemd5
        csv_fields_joined.add(fn_ep.toString().toUpperCase()); // fn_addr
        csv_fields_joined.add(Integer.toString(fnu.code_units.size())); // num_basic_blocks
        csv_fields_joined.add(Integer.toString(fnu.code_units.size())); // num_basic_blocks_in_cfg, TODO:check this, should this be different from num_basic_blocks?
        csv_fields_joined.add(Integer.toString(fnu.num_insn)); // num_instructions
        csv_fields_joined.add(Integer.toString(fnu.num_bytes)); // num_bytes
        csv_fields_joined.add(byteArrayToHexString(fnu.ehash,"")); // exact_hash
        csv_fields_joined.add(byteArrayToHexString(fnu.phash,"")); // pic_hash
        csv_fields_joined.add(byteArrayToHexString(fnu.cphash,"")); // composite_pic_hash
        csv_fields_joined.add(byteArrayToHexString(fnu.mhash,"")); // mnemonic_hash
        csv_fields_joined.add(byteArrayToHexString(mcnthash,"")); // mnemonic_count_hash
        csv_fields_joined.add(byteArrayToHexString(fnu.mchash,"")); // mnemonic_category_hash
        csv_fields_joined.add(byteArrayToHexString(mccnthash,"")); // mnemonic_category_counts_hash
        // emit exact and PIC bytes if --dump option seen
        if (flag_dump) {
        csv_fields_joined.add(fn_ebytes_string);
        csv_fields_joined.add(fn_pbytes_string);
        }
        csv_fields_joined.add(fn_insncnt_joined.toString()); // mnemonic_count_string
        csv_fields_joined.add(fn_insncatcnt_joined.toString()); // mnemonic_category_count_string
    
        msg = csv_fields_joined.toString();
        */

        return false;
    }

    @Override
    public List<Option> getOptions(DomainObjectService domainObjectService) {
        List<Option> list = new ArrayList<>();

        // TODO: If this exporter has custom options, add them to 'list'
        list.add(new Option("Option name goes here", "Default option value goes here"));

        return list;
    }

    @Override
    public void setOptions(List<Option> options) throws OptionException {

        // TODO: If this exporter has custom options, assign their values to the exporter here
    }
}
