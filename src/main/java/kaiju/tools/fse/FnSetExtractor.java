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
package kaiju.tools.fse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;
import java.util.Vector;

import db.NoTransactionException;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.ConsoleTaskMonitor;
import kaiju.common.KaijuLogger;
import kaiju.common.KaijuPropertyManager;
import kaiju.hashing.FnHashSaveable;

public class FnSetExtractor implements KaijuLogger {

    // A Map of: function pic hash -> program md5 -> list of entry point addresses.
    private TreeMap<String, TreeMap<String, List<Address>>> fn2file;
    // A Map of: program md5 -> function pic hash -> list of entry point addresses.
    private TreeMap<String, TreeMap<String, List<Address>>> file2fn;
    // A Map of: program md5 -> program name.
    private TreeMap<String, String> fileHash2Name;
    // A Map of: fnhash -> string vector of files containing hash (made of 0s and 1s) -> count.
    private TreeMap<String, TreeMap<String, Integer>> fn2hashveccnt;
    // A Map of: fnhash -> string vector of files containing hash (made of 0s and 1s).
    private TreeMap<String, String> fn2hashvec;
    // A Map of: string vector of files containing hash (made of 0s and 1s) -> vector of
    //           ExtractedFunctions that contain pic hash, and num of bytes & insns
    private TreeMap<String, Vector<ExtractedFunction>> hashvec2fn;
    // easy tracking of number of programs in the project
    private int numOfProgramsInProject;

    public FnSetExtractor(ProjectData currentData) {
        // ensures this object cannot be created without doing computation
        // and initializing all private member variables
        computeFnSet(currentData);
    }
    
    public TreeMap<String, TreeMap<String, List<Address>>> getFn2File() {
        return fn2file;
    }
    
    public TreeMap<String, TreeMap<String, List<Address>>> getFile2Fn() {
        return file2fn;
    }
    
    public TreeMap<String, TreeMap<String, Integer>> getFn2HashVecCnt() {
        return fn2hashveccnt;
    }
    
    public TreeMap<String, String> getFn2HashVec() {
        return fn2hashvec;
    }
    
    public TreeMap<String, Vector<ExtractedFunction>> getHashVec2Fn() {
        return hashvec2fn;
    }
    
    public TreeMap<String, String> getFileHash2Name() {
        return fileHash2Name;
    }
    
    public int getNumOfProgramsInProject() {
        return numOfProgramsInProject;
    }

    /**
     * Compute functions.
     * Private function, called automatically when object is created.
     */
    private void computeFnSet(ProjectData currentData) {
    
        // monitor this task
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        
        // reset program counter
        numOfProgramsInProject = 0;
    
        // get a list of programs in this project
        //ProjectData currentData = currentProject.getProjectData();
        DomainFolder rootFolder = currentData.getRootFolder();
        DomainFile[] domainFileList = rootFolder.getFiles();
        
        List<Program> projectProgs = new ArrayList<Program>();
        for (DomainFile dFile : domainFileList) {
            try {
                DomainObject dObj = dFile.getDomainObject(this, true, true, monitor);
                //dFile instanceof Program
                if (dObj instanceof Program) {
                    // casting DomainObject to Program after we check it is the right type
                    projectProgs.add( (Program) dObj);
                }
            } catch (VersionException ve) {
                // TODO: what do we do with the exception?
            } catch (IOException ie) {
                // TODO: what do we do with the exception?
            } catch (CancelledException ce) {
                // TODO: what do we do with the exception?
            };
        };
        
        // now we have a list of Programs.
        
        fn2file = new TreeMap<>();
        file2fn = new TreeMap<>();
        fileHash2Name = new TreeMap<>();
        
        TreeMap<String, Integer> fn2numbytes = new TreeMap<>();
        TreeMap<String, Integer> fn2numinsns = new TreeMap<>();
        
        for (Program currentProgram : projectProgs) {
        
            numOfProgramsInProject++;
        
            String fmd5 = currentProgram.getExecutableMD5();
            fileHash2Name.put(fmd5, currentProgram.getName());
        
            FunctionIterator fiter = currentProgram.getFunctionManager().getFunctions(true);
            
            while (fiter.hasNext()) {
                Function function = fiter.next();
                if (function == null) {
                    debug(this, "Skipping Null Function Reference");
                    continue;
                }
                if (function.isThunk()) {
                    debug(this, "Skipping Thunk @ 0x" + function.getEntryPoint().toString());
                    continue;
                }
                
                ObjectPropertyMap fnhashmap = null;
            
                // TODO: this needs a better error handling procedure
                try {
                    fnhashmap = KaijuPropertyManager.getOrCreateObjectPropertyMap(currentProgram, "FnHash", FnHashSaveable.class);
                } catch (NoTransactionException nte) {
                    // TODO: what do we do with the exception?
                }
                
                if (fnhashmap != null) {
                
                    FnHashSaveable prop = null;
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
                            prop = (FnHashSaveable) c.getDeclaredMethod("get").invoke(function.getEntryPoint());
                        } catch (Exception e) {
                            //TODO
                            return;
                        }
                    } catch(NoSuchMethodException e) {
                        // before Ghidra 10.2, it was getObject()
                        try {
                            prop = (FnHashSaveable) c.getDeclaredMethod("getObject").invoke(function.getEntryPoint());
                        } catch (Exception e2) {
                            //TODO
                            return;
                        }
                    }
                    //FnHashSaveable prop = (FnHashSaveable) fnhashmap.getObject(function.getEntryPoint());
                    
                    if (prop != null) {
                        // TODO: make it configurable which type of hash to use here
                        String fnhash = prop.getPICHash();
                        Integer numbytes = prop.getNumBytes();
                        Integer numinsns = prop.getNumInstructions();
                        
                        if (fnhash == null) continue;
                        
                        fn2numbytes.put(fnhash, numbytes);
                        fn2numinsns.put(fnhash, numinsns);
                        
                        if (fn2file.containsKey(fnhash)) {
                            if (fn2file.get(fnhash).containsKey(fmd5)) {
                                List<Address> values = fn2file.get(fnhash).get(fmd5);
                                values.add(function.getEntryPoint());
                                fn2file.get(fnhash).put(fmd5, values);
                            } else {
                                List<Address> values = new ArrayList<Address>();
                                values.add(function.getEntryPoint());
                                fn2file.get(fnhash).put(fmd5, values);
                            }
                        } else {
                            TreeMap<String, List<Address>> values = new TreeMap<>();
                            List<Address> vallist = new ArrayList<Address>();
                            vallist.add(function.getEntryPoint());
                            values.put(fmd5, vallist);
                            fn2file.put(fnhash, values);
                        }
                        
                        if (file2fn.containsKey(fmd5)) {
                            if (file2fn.get(fmd5).containsKey(fnhash)) {
                                List<Address> values = file2fn.get(fmd5).get(fnhash);
                                values.add(function.getEntryPoint());
                                file2fn.get(fmd5).put(fnhash, values);
                            } else {
                                List<Address> values = new ArrayList<Address>();
                                values.add(function.getEntryPoint());
                                file2fn.get(fmd5).put(fnhash, values);
                            }
                        } else {
                            TreeMap<String, List<Address>> values = new TreeMap<>();
                            List<Address> vallist = new ArrayList<Address>();
                            vallist.add(function.getEntryPoint());
                            values.put(fnhash, vallist);
                            file2fn.put(fmd5, values);
                        }
                    }
                }
            }
        };
        
        TreeMap<String, Integer> num_fn_per_file = new TreeMap<>();
        for (String f : file2fn.keySet()) {
            num_fn_per_file.put(f, file2fn.get(f).size());
        }
        
        // now do stuff with fn2file
        fn2hashvec = new TreeMap<>();
        fn2hashveccnt = new TreeMap<>();
        hashvec2fn = new TreeMap<>();
        for (String fn : fn2file.keySet()) {
            String vec = "";
            Integer cnt = 0;
            
            for (String f : num_fn_per_file.descendingKeySet()) {
                if (file2fn.get(f).containsKey(fn)) {
                    vec += "1";
                    cnt += 1;
                } else {
                    vec += "0";
                }
            }
            TreeMap<String, Integer> vecVal = new TreeMap<>();
            vecVal.put(vec, cnt);
            fn2hashveccnt.put(fn, vecVal);
            fn2hashvec.put(fn, vec);
                
            if (hashvec2fn.containsKey(vec)) {
                Vector<ExtractedFunction> fnvec = hashvec2fn.get(vec);
                fnvec.add(new ExtractedFunction(fn, fn2numinsns.get(fn), fn2numbytes.get(fn)));
                hashvec2fn.put(vec, fnvec);
            } else {
                Vector<ExtractedFunction> fnvec = new Vector<>();
                fnvec.add(new ExtractedFunction(fn, fn2numinsns.get(fn), fn2numbytes.get(fn)));
                hashvec2fn.put(vec, fnvec);
            }
            
        }
        
    }
    
}
