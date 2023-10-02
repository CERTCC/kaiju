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

// For UTF8 charset in crypto functions to standardize across operating systems
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.TreeMap;

import ghidra.app.services.BlockModelService;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.code.CodeManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.UsrException;
import ghidra.util.task.TaskMonitor;
import kaiju.disasm.context.InsnContext;
import kaiju.util.ByteArrayList;

/**
 * an inner class to gather Function data for hashing purposes, providing
 * utility functions for it. It also currently saves the bytes hashed for both
 * EXACT and PIC hashes.
 * The default scheme for ordering these bytes is at the BasicBlock level ordered by Address.
 * There is an option for ordering the bytes by control flow as defined by 
 * @param function A function in a program
 */
public class FnUtils {

    public Function function;
    public Address fep;
    public CodeBlock fep_bb;
    public CodeUnit fep_cu;
    public AddressSetView allAddresses;
    public AddressSetView chunks;
    public CodeBlockModel bb_model;
    public List<CodeBlock> basic_blocks;
    public List<CodeUnit> code_units; // in address order
    public Map<CodeBlock,List<CodeBlock>> bbflowsto; // map to get bb flow order within the function
    public List<CodeBlock> basic_blocks_in_flow_order; // in flow order
    public List<CodeUnit> code_units_in_address_order;
    public List<UnitHashData> code_unit_hash_data_in_address_order;
    public List<BlockHashData> basic_block_hash_data_in_flow_order;
    public List<BlockHashData> basic_block_hash_data_in_address_order;
    
    // map to hold counts for Instruction mnemonics and categories
    public TreeMap<String,Integer> fn_insncnt;
    public TreeMap<String,Integer> fn_insncatcnt;
 
    public CodeManager cm;
    public byte [] ehash;
    public byte [] phash;
    public byte [] cphash; // composite pic hash
    public byte [] mhash; // mnemonic hash
    public byte [] mchash; // mnemonic category hash
    public List<byte []> fn_ebytes;
    public List<byte []> fn_pbytes;
    public List<byte []> fn_pmask; // PIC mask, 1 for address, 0 for else, for YARA signature generation
    public List<byte []> fn_cpbytes;
    public int num_insn;
    public int num_bytes;
    
    public byte[] getExactBytes() {
        ByteArrayList result = new ByteArrayList();
        for (byte[] ba : fn_ebytes) {
            result.add(ba);
        }
        return result.toArray();
    }
    
    public List<byte []> getExactBytesList() {
        return fn_ebytes;
    }
    
    public byte[] getPICBytes() {
        ByteArrayList result = new ByteArrayList();
        for (byte[] ba : fn_pbytes) {
            result.add(ba);
        }
        return result.toArray();
    }
    
    public List<byte []> getPICBytesList() {
        return fn_pbytes;
    }
    
    public List<byte []> getPICMask() {
        return fn_pmask;
    }

    public FnUtils(Program currentProgram, TaskMonitor monitor) throws Exception {

	// if no function passed, assume null function
        // no Function structure here as we assume this will be externally assigned
        function = null;
        fep = null;
        
        // figure out which architecture ghidra thinks this is
        // (can also be instruction specific when accessed via the InstructionPrototype
        //  which we may want with programs that may have multiple processors defined 
        //  e.g., ARM with Thumb?)
        
        String arch = currentProgram.getLanguage().getProcessor().toString();
        //info("Arch is " + arch);
        InsnContext insn_context = new InsnContext();
        try {
            insn_context.setCategorizerStrategy(arch);
        } catch (Exception e) {
            throw new Exception("Could not set CategorizerStrategy, arch was: " + arch + ", exception was: " + e.toString());
        }
        if (insn_context.getValidCategories() == null) { throw new Exception("NullPointerException while getting getValidCategories()!"); }

        num_insn = 0;
        num_bytes = 0;

        // These need to be empty to produce empty/null hash
        fn_ebytes = new ArrayList<byte []>();
        fn_pbytes = new ArrayList<byte []>();
        fn_pmask = new ArrayList<byte []>();
        fn_cpbytes = new ArrayList<byte []>();
        
        allAddresses = null;
        chunks= null;
       
        // This is probably only needed for GUI interaction
        cm = null;
        
        // These are instantiated by MessageDigest
        //byte [] ehash;
        //byte [] phash;        
        
        fep_cu = null;
        code_units = new LinkedList<CodeUnit>();
        code_units_in_address_order = new LinkedList<CodeUnit>();
        code_unit_hash_data_in_address_order = new LinkedList<UnitHashData>();


        fep_bb = null;
        basic_blocks = new LinkedList<CodeBlock>();
        bbflowsto = new HashMap<CodeBlock,List<CodeBlock>>();
        basic_blocks_in_flow_order = new LinkedList<CodeBlock>();
        basic_block_hash_data_in_flow_order = new LinkedList<BlockHashData>();
        basic_block_hash_data_in_address_order = new LinkedList<BlockHashData>();

        bb_model = null;
        
        fn_insncnt = new TreeMap<>();
        fn_insncatcnt = new TreeMap<>();
        // TODO: test for arch NOT getting set in insn_cat_map when no arch
        // defined for current instruction/program
        for (String catname: insn_context.getValidCategories()) {
            // pre-set categories to 0 counts
            fn_insncatcnt.put(catname, 0);
        };
	}

    // CTOR: CodeUnit Address order hashing
    // Note this does not (likely) pick up Data CodeUnits at the present time
    // As it  appears the Namespace/Function.getBody() method excludes them.
    // Iterating from the FEP Address to the max Address of the last CodeUnit
    // may be the only way to cover both Code and Data (and Undefined CodeUnits, FTR)
    // @param function A Function in the body of the program
    // @throws UsrException An exception is thrown if the function has unexpected data in a CodeUnit 
    public FnUtils(Function fn, Program currentProgram, TaskMonitor monitor) throws Exception, UsrException {
      
      // figure out which architecture ghidra thinks this is
      // (can also be instruction specific when accessed via the InstructionPrototype
      //  which we may want with programs that may have multiple processors defined 
      //  e.g., ARM with Thumb?)
        
      String arch = currentProgram.getLanguage().getProcessor().toString();
      // TODO: can we assume arch is always set?
      //info("Arch is " + arch);
      InsnContext insn_context = new InsnContext();
      try {
            insn_context.setCategorizerStrategy(arch);
        } catch (Exception e) {
            // TODO: give the user some kind of warning
        }
    
      function = fn;

      num_insn = 0;

      fn_ebytes = new ArrayList<byte []>();
      fn_pbytes = new ArrayList<byte []>();
      fn_pmask = new ArrayList<byte []>();
      fn_cpbytes = new ArrayList<byte []>();

      code_units = new LinkedList<CodeUnit>();
      //bbflowsto = new HashMap<CodeBlock,List<CodeBlock>>();
      code_units_in_address_order = new LinkedList<CodeUnit>();
      //basic_block_hash_data_in_address_order = new LinkedList<UnitHashData>();
      code_unit_hash_data_in_address_order = new LinkedList<UnitHashData>();
      
      fn_insncnt = new TreeMap<>();
      fn_insncatcnt = new TreeMap<>();
      for (String catname: insn_context.getValidCategories()) {
        // pre-set categories to 0 counts
        fn_insncatcnt.put(catname, 0);
      };

      //bb_model = null;  
      
      //PriorityQueue<Address> basic_block_priority_queue = new PriorityQueue<Address>();
      
      String msg; // for debugging output
      
      
      // the CodeManager can be used to look up instruction stuff later, but
      // it's not exposed in the Program interface so we need to cast to the
      // underlying ProgramDB implementation of currentProgram to get at that:
      cm = ((ProgramDB)currentProgram).getCodeManager();
            
      fep = function.getEntryPoint();
      
      
      // Also sets allAddresses
      int numAddrs = getFnAddresses();
      //debug("Function @" + fep.toString() + " has " + numAddrs + " code units");
      
      // For interactive use potentially when instantiating a progress bar
      monitor.initialize(allAddresses.getNumAddresses());

      // Turns out that in headless mode the state.getTool() returns null.
      // in fact, could use that to simply iterate over all of the
      // instructions of the function directly, in address order, if that
      // suffices for something, like so:
      CodeUnitIterator cuIter = cm.getCodeUnits(allAddresses,true);

      if (cuIter == null) {
          //debug("No CodeUnits found!");
          // TODO: if no CU's, should probably bail or throw an Exception
          // maybe EmptyFunctionException?
      }      
      
      // int numBasicBlocks = getBasicBlocks();
      // //debug("Function @" + fep.toString() + " has " + numBasicBlocks + " basic blocks");
      
      
      // TODO: Break this work queue logic out into own private Class method
      
      HashSet<CodeUnit> beenThere = new HashSet<>(); // already worked off
      Queue<CodeUnit> worklist = new LinkedList<>();
      //ep_bb = bbm.getFirstCodeBlockContaining(ep,monitor);
      //fep_bb = bb_model.getCodeBlockAt(fep,monitor);
      //could also iterate through bb's and see which one(s) contain fep

      
 
      fep_cu = cuIter.next();
      if (fep_cu != null && !fep_cu.contains(fep)) {
        //debug("Function entry point not in first CodeUnit!");
      }
     
      // well, processed "all" the CodeUnits now,
      // so can now produce EHASH & PHASH data for the function:
      MessageDigest emd5 = MessageDigest.getInstance("MD5"); // exact_hash
      MessageDigest pmd5 = MessageDigest.getInstance("MD5"); // pic_hash
      MessageDigest cpmd5 = MessageDigest.getInstance("MD5");// composite_pic_hash
      MessageDigest mmd5 = MessageDigest.getInstance("MD5"); // mnemonic_hash
      MessageDigest mcmd5 = MessageDigest.getInstance("MD5");// mnemonic_category_hash
      
      worklist.add(fep_cu); 
      // now work off the worklist:
      while (!worklist.isEmpty()) {
        CodeUnit cur_cu = worklist.remove();
        if (beenThere.contains(cur_cu)) {
          continue;
        }
        // when I forgot to cull out null blocks:
        if (cur_cu == null) {
          ////debug("NULL CUR_CU");
          continue;
        }
        beenThere.add(cur_cu);
        code_units_in_address_order.add(cur_cu);
        
       	msg = "Processing cu from Addresses " + cur_cu.getMinAddress().toString() + " -> " + cur_cu.getMaxAddress().toString();
       	
    	//debug(msg);

        // compute CodeUnit level hash info here:
    	//UnitHashData cuhd = null;
    	// throws UsrError if unexpected data found in CodeUnit flow
    	UnitHashData cuhd = new UnitHashData(cur_cu, cm, monitor);
    	// DO NOT catch exception here as we want to propagate up to function level
    	// to "unset" entire function set of CU's
    	// ALTERNATELY could "zero-out" bad CU, but empirically we have found eith the entire function
    	// has unexpected data CU's or bad program analysis has led to a series of "bad" CU's invalidating 
    	// a structured hashing approach.
    	num_insn += cuhd.insns.size();
    	num_bytes += cuhd.num_bytes;

        cuhd.is_ep = cur_cu.getMinAddress().equals(fep);
        // we'll compute fn level hash from this later:
        code_unit_hash_data_in_address_order.add(cuhd);
        
        // need ebytes & pbytes for each instruction we saved off:
        // saving raw bytes for each function if needed later
        // this may cause unacceptable memory or performance issues...
        for (byte [] ebytes: cuhd.ebytes) {
            fn_ebytes.add(ebytes);
            emd5.update(ebytes);
        }
        for (byte [] pbytes: cuhd.pbytes) {
            fn_pbytes.add(pbytes);
            pmd5.update(pbytes);
        }
        for (byte [] pmask: cuhd.pmask) {
            fn_pmask.add(pmask);
        }
        
        worklist.add(cuIter.next());
        
        // update mnemonic and mnemonic counts for this CodeUnit
        String insnmnem = cur_cu.getMnemonicString();
        if (fn_insncnt.get(insnmnem) == null) {
            // insn is not currently in map, so set to initial value of 1
            fn_insncnt.put(insnmnem, 1);
        } else {
            // insn was already in map, so increment it
            fn_insncnt.put(insnmnem, fn_insncnt.get(insnmnem) + 1);
        }
        
        // add mnemonic string to calculate mnemonic hash
        mmd5.update(insnmnem.getBytes(StandardCharsets.UTF_8));
        
        // REGRESSION TESTING
        String insncat = insn_context.getInsnCategory(cur_cu);
        //info("Insncat is " + insncat);
        // REGRESSION HERE: NOP was not in x86Categories, leading to uninitialized insncatcnt and NULL dereference
        // looks like a bug in the original pharos::misc::get_all_insn_generic_categories() function implemented
        // by fn2hash...
        // Need to sync categories in regex with {arch}Categories OR use different logic here,
        // perhaps by not having a static structure listing the categories at all (instead iterating from the 
        // dynamically-created one?)
        fn_insncatcnt.put(insncat, fn_insncatcnt.get(insncat) + 1);
        
        // add mnemonic category string to calculate mnemonic category hash
	// TODO: test to see if this instance of getBytes() needs StandardCharsets.UTF_8 set as arg
        mcmd5.update(insncat.getBytes(StandardCharsets.UTF_8));
        
        // save the cpbytes for composite pic if not control flow insn
        if (insncat != "BR") {
            for (byte [] cpbytes: cuhd.pbytes) {
                fn_cpbytes.add(cpbytes);
                cpmd5.update(cpbytes);
            }
        }
        
      } // while !worklist.isEmpty()
      
      // end work queue logic

      // All CU's in function *should* be accounted for now.
      
      ehash = emd5.digest();
      phash = pmd5.digest();
      cphash = cpmd5.digest();
      mhash = mmd5.digest();
      mchash = mcmd5.digest(); // mnemonic_category_hash 

    } // end of FnWrapper CTOR
    
    private int getFnAddresses() {
    	String dmsg;
    	int nChunks = 0;
    	int nAddresses = 0;
    	
    	AddressSet addrs = new AddressSet();
    	
    	if (function == null ) {
    		return 0;
    	}
    	
    	nChunks = getChunks();
    	//debug("Fn has " + nChunks + " chunk(s)");

    	
    	// note this should include Data (but NOT Unknown) CodeUnits as well 
    	CodeUnitIterator cuiter = cm.getCodeUnits(chunks,true);
    	
    	if (!cuiter.hasNext()) {
    		//debug("Empty CodeUnit Iterator in Function!");
    	}
    	
    	for (CodeUnit cu: cuiter) {
    		addrs.add(cu.getAddress());
    		code_units.add(cu);
    		nAddresses++;
    		
    		dmsg = "  ";
    		dmsg += "CodeUnit from " + cu.getMinAddress().toString() + " to " + cu.getMaxAddress().toString();
    		//debug(dmsg);
    	}
    	
    	allAddresses = (AddressSetView) addrs;
    	
    	return nAddresses;
    	
    }
    
    private int getChunks() {
    	
    	String dmsg;
    	int nchunks;
    	
    	if (function == null) {
    		//debug("Empty function found!");
    		return 0;
    	}
    	
    	// no real simple API to get Chunks/BasicBlocks(CodeBlocks)/Instructions
    	// from a Function, well except for the "chunks" I suppose that come
    	// back as the body of the function as an AddressSetView:
    	chunks = function.getBody();
    	
    	nchunks = 0;
    	for (AddressRange chunk: chunks) {
    		dmsg = "  ";
    		nchunks++;
    		
    		if (chunk.contains(fep)) {
    			dmsg += "[FnEP] ";
    		}
    		// if (chunk.getMinAddress() < ep) { // odd, this doesn't work, and
    		// there is no toLong() method?  But there is a compareTo(), which
    		// does work:
    		if (chunk.getMinAddress().compareTo(fep) < 0) {
    			dmsg += "[pre EP] ";
    		}
    		dmsg += "chunk from " + chunk.getMinAddress().toString() + " to " + chunk.getMaxAddress().toString();
    		//debug(dmsg);
    	}
    	return nchunks;
    }

    private int getBasicBlocks(Program currentProgram, TaskMonitor monitor) throws CancelledException {
    	
    	int nblocks = 0;
        CodeBlockIterator bbiter = null;    	

        // could/should perhaps just do this based in isRunningHeadless() answer?
        try {
          // get an iterator over the CodeBlocks (basic blocks, maybe data too?)
          // via the BlockModelService & the function chunks:
          // NOTE: following line was working in original GhidraScript
          //BlockModelService blockModelService = state.getTool().getService(BlockModelService.class);
          ServiceProviderStub sps = new ServiceProviderStub();
          BlockModelService blockModelService = sps.getService(BlockModelService.class);
          ////debug("the active block model is: " + blockModelService.getActiveBlockModelName());
          //bbm = blockModelService.getActiveBlockModel();
          // note that the default active block model seems to be the
          // SimpleBlockModel, but just in case that ever changes, I want to
          // explicitly ask for the SimpleBlockModel because it will end a block
          // at a CALL where the BasicBlolckModel does not, and I don't want to
          // be surprised if the default changes for some reason:
          try {
        	  bb_model = blockModelService.getNewModelByName(blockModelService.SIMPLE_BLOCK_MODEL_NAME);
          } catch (ghidra.util.exception.NotFoundException nfe) {
        	  // TODO: catch me if you can
          }

        } catch (NullPointerException npe) {
          // Could also create a new model, which seems to be how the
          // FunctionGraph plugin does it, but seems more correct to reuse the one
          // that the service provides:
          //bbm = new BasicBlockModel(currentProgram);
          // and as I discovered from above, the default SimpleBlockModel is
          // actually what I want as it will end a block at a CALL where the
          // BasicBlockModel doesn't (and EXCLUDE externals):
      	  bb_model = new SimpleBlockModel(currentProgram, false);
          
        }
        
        // TODO: probably need to wrap this in try/catch and throw an error if cancelled
        bbiter = bb_model.getCodeBlocksContaining(chunks, monitor);
        
        // can now iterate over the basic blocks getting addresses, not sure how
        // to get at instructions "properly" yet...
        for (;bbiter.hasNext();) {
          nblocks++;
          CodeBlock bb = bbiter.next();

          basic_blocks.add(bb); // save this off for later

          //dumpBB(bb);
        }
        
        return nblocks;
    }
    
  } // end of FnUtils
