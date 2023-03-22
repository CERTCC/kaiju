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

// For UTF8 charset in crypto functions to standardize across operating systems
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.StringJoiner;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.UsrException;
import ghidra.util.task.TaskMonitor;
import kaiju.common.KaijuLogger;
import kaiju.common.KaijuPropertyManager;
import kaiju.common.logging.MultiLogLevel;
import kaiju.hashing.FnHashSaveable;
import kaiju.tools.fnhashclassic.FnUtils;
import kaiju.util.HexUtils;

/**
 * A Ghidra analyzer pass that calculates function hashes within a Program.
 * Documentation for analyzers is at:
 * https://ghidra.re/ghidra_docs/api/ghidra/app/services/AbstractAnalyzer.html
 */
public class FnHashAnalyzer extends AbstractAnalyzer implements KaijuLogger {

    // the strings for names and descriptions of this analyzer and its options
    // are available in kaiju.fnhash.FnHashOptions, so that other classes
    // can access these values for working with the Ghidra database

    private Integer min_insns;
    
    private boolean include_basic_blocks;

    /**
     * Creates an Fn2Hash instance and registers its name and description within Ghidra.
     */
    public FnHashAnalyzer() {
        super(FnHashOptions.NAME, FnHashOptions.DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
        // hashing works best after CERT Disassembly Improvements is run, so
        // set the priority to be afterward. Lowest priority ever to ensure
        // all the other analyzers run first.
        // https://ghidra.re/ghidra_docs/api/ghidra/app/services/AnalysisPriority.html
        setPriority(AnalysisPriority.LOW_PRIORITY.after());
        // initialize analyzer options including logger
        min_insns = FnHashOptions.MIN_INSNS_OPTION_DEFAULT;
        include_basic_blocks = FnHashOptions.BASIC_BLOCK_OPTION_DEFAULT;
    }

    /**
     * Sets Fn2Hash to be enabled by default by returning true.
     */
    @Override
    public boolean getDefaultEnablement(Program program) {
        return true;
    }

    /**
     * Examine 'program' to determine if Fn2Hash should analyze it.
     * Returns true if the program can be analyzed by Fn2Hash.
     * This should work for pretty much any program, so just return true by default now.
     * TODO: Should we check for an executable container format? Arch with supported categories?
     */
    @Override
    public boolean canAnalyze(Program program) {
        return true;
    }

    /**
     * Registers custom analyzer options and default settings for Fn2Hash.
     * Users may edit these options in the AutoAnalyzer dialog of Ghidra.
     * Options defaults are set based on user custom values saved for this program.
     */
    @Override
    public void registerOptions(Options options, Program program) {

        options.registerOption(
            FnHashOptions.MIN_INSNS_OPTION_NAME,
            OptionType.INT_TYPE,
            FnHashOptions.MIN_INSNS_OPTION_DEFAULT,
            null,
            "Set the minimum number of instructions needed to output data for a function"
        );
        
        options.registerOption(
            FnHashOptions.BASIC_BLOCK_OPTION_NAME,
            FnHashOptions.BASIC_BLOCK_OPTION_DEFAULT,
            null,
            "Check if optional basic block level data should be included in output data"
        );
        
        options.registerOption(
            FnHashOptions.LOG_LEVEL_OPTION_NAME,
            OptionType.ENUM_TYPE,
            MultiLogLevel.WARN,
            null,
            "Set the minimum log level to be displayed in GUI messages, console, and application log"
        );
    }
    
    /**
     * Handle user changes of options.
     */
    @Override
    public void optionsChanged(Options options, Program program) {

        if (options.contains(FnHashOptions.MIN_INSNS_OPTION_NAME)) {
            min_insns = options.getInt(FnHashOptions.MIN_INSNS_OPTION_NAME, FnHashOptions.MIN_INSNS_OPTION_DEFAULT);
        }
        
        if (options.contains(FnHashOptions.BASIC_BLOCK_OPTION_NAME)) {
            include_basic_blocks = options.getBoolean(FnHashOptions.BASIC_BLOCK_OPTION_NAME, FnHashOptions.BASIC_BLOCK_OPTION_DEFAULT);
        }
        
        if (options.contains(FnHashOptions.LOG_LEVEL_OPTION_NAME)) {
            setLogLevel(options.getEnum(FnHashOptions.LOG_LEVEL_OPTION_NAME, MultiLogLevel.WARN));
        }
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
            
        // try to get FnHashAnalyzer properties, if analyzer has been run
        Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
        
        // set up property maps to store hash data in ghidra program database
        ObjectPropertyMap<FnHashSaveable> fnhashobjmap = KaijuPropertyManager.getOrCreateObjectPropertyMap(program, "FnHash", FnHashSaveable.class);
        
        // start analyzing functions
        // iterate over all functions (if not currently in a function or if running headless):
        FunctionIterator fiter = program.getFunctionManager().getFunctions(true);
            
        int fncount = 0;
        if (fiter == null) {
            warn(this, "No functions found?");
        } else {
            while (fiter.hasNext()) {
                Function function = fiter.next();
                if (monitor.isCancelled()) {
                    break;
                }
                if (function == null) {
                    info(this, "Skipping Null Function Reference");
                    continue;
                }
                if (function.isThunk()) {
                    info(this, "Skipping Thunk @ 0x" + function.getEntryPoint().toString());
                    continue;
                }
                try {
                    FnHashSaveable hashresult = runOneFn(function, program, monitor);
                    fnhashobjmap.add(function.getEntryPoint(), hashresult);
                    fncount++;
                    info(this, "Adding Function @ 0x" + function.getEntryPoint().toString());
                } catch (Exception e) {
                    error(this, "Error while computing function hashes", e);
                }
            }
        }
        
        info(this, "Fn2Hash analysis complete: Found hashes for " + fncount + " functions.");
        //debug(this, ManualViewerCommandWrappedOption().getCommandString);
        
        // return true if analysis succeeded
        return true;
    }
    
    private FnHashSaveable runOneFn(Function function, Program program, TaskMonitor monitor) throws Exception {
        
        Address fn_ep = function.getEntryPoint();
        String msg = ">>> " + function.getName() + " @ 0x" + fn_ep;
        monitor.setMessage(msg);
        debug(this, msg);
        
        // TODO: gets null pointer here if no program is open
        // in headless mode
        String fmd5 = program.getExecutableMD5();
        
        // TODO: catch UsrException here and dummy up missing fields in fnu
        FnUtils fnu = null;
        try {
            fnu = new FnUtils(function, program, monitor);
        } catch (UsrException usrEx) {
            // set any function specifics that don't include bytes
            fnu = new FnUtils(program, monitor);
            fnu.fep = fn_ep;
            // enough for now
        } catch (Exception e) {
            // TODO: can we do something better here?
            warn(this, "Exception caught while computing hashes", e);
            return new FnHashSaveable();
        }
        //fnu.dumpFn(false); // turn off dumping BB's for now
        
        // now output hash data, CSV format sort of matching fn2hash:
        //   filemd5,fnaddr,numbb,numinsn,numbytes,ehash,phash
        // eventually add:
        //   ebytes,pbytes (TESTING -- make optional?)
        //   insn-type-counts (TESTING -- do these compare with pharos implementation?)
        //   cphash,mnemhash,mnemcnthash,mnemcathash,mnemcatcnthash,mnemcntvec,mnemcatcntvec,bbinfo,bbcfginfo

        // need a better way to handle the List fn_[ep]bytes... trying to avoid
        // repeated calls to HexUtils.byteArrayToHexString(); could build byte array instead
        // but feels better to inline string for output
        String fn_ebytes_string = "";
        String fn_pbytes_string = "";
        for (byte [] feb : fnu.fn_ebytes) {
            for (byte eb: feb) {
                fn_ebytes_string += String.format("%02X%s",eb,"");
            }
        }
        for (byte [] fpb : fnu.fn_pbytes) {
            for (byte pb: fpb) {
                fn_pbytes_string += String.format("%02X%s",pb,"");
            }
        }
        // TODO: refactor so either code_units.size() or basic_blocks.size() works here
        // Oddly, when just basic_blocks.size() in CodeUnit mode I seemed to be getting silent errors
        // /exceptions at runtime that caused the program execution to stop for no apparent reason...
        
        // REGRESSION TESTING
        // form instruction and category counts as CSV string
        // using StringJoiner solves the extra ';' at the end problem
        //String fn_insncnt_string = "";
        StringJoiner fn_insncnt_joined = new StringJoiner(";");
        //String fn_insncatcnt_string = "";
        StringJoiner fn_insncatcnt_joined = new StringJoiner(";");
        for (String key : fnu.fn_insncnt.keySet()) {
            //fn_insncnt_string += key.toLowerCase() + ":" + fnu.fn_insncnt.get(key);
            fn_insncnt_joined.add(key.toLowerCase() + ":" + fnu.fn_insncnt.get(key)); 
        }
        
        for (String key : fnu.fn_insncatcnt.keySet()) {
            //fn_insncatcnt_string += key + ":" + fnu.fn_insncatcnt.get(key);
            fn_insncatcnt_joined.add(key + ":" + fnu.fn_insncatcnt.get(key)); 
        }
        
        // compute mnemonic_count_hash
        MessageDigest mcntmd5 = MessageDigest.getInstance("MD5");
        byte[] mcnthash = mcntmd5.digest(fn_insncnt_joined.toString().getBytes(StandardCharsets.UTF_8));
        
        // compute mnemonic_category_counts_hash
        MessageDigest mccntmd5 = MessageDigest.getInstance("MD5");
        byte[] mccnthash = mccntmd5.digest(fn_insncatcnt_joined.toString().getBytes(StandardCharsets.UTF_8));
        
        return new FnHashSaveable(fmd5.toUpperCase(),
                                  fn_ep.toString().toUpperCase(),
                                  fnu.code_units.size(),
                                  fnu.code_units.size(), // TODO: should CFG size be different?
                                  fnu.num_insn,
                                  fnu.num_bytes,
                                  fn_insncnt_joined.toString(),
                                  fn_insncatcnt_joined.toString(),
                                  fnu.getExactBytes(),
                                  HexUtils.byteArrayToHexString(fnu.ehash,""),
                                  fnu.getPICBytes(),
                                  HexUtils.byteArrayToHexString(fnu.phash,""),
                                  HexUtils.byteArrayToHexString(fnu.cphash,""),
                                  HexUtils.byteArrayToHexString(fnu.mhash,""),
                                  HexUtils.byteArrayToHexString(mcnthash,""),
                                  HexUtils.byteArrayToHexString(fnu.mchash,""),
                                  HexUtils.byteArrayToHexString(mccnthash,""));
        
    }
}
