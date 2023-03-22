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
import java.io.File;
import java.io.StringWriter;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.List;
// HeadlessScript used so doesn't appear in Ghidra GUI
import ghidra.app.script.GhidraScript;
//import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import kaiju.hashing.FnHashSaveable;
import kaiju.tools.fnhashclassic.FnUtils;
import kaiju.util.ByteArrayList;
import kaiju.util.HexUtils;

public class KaijuExportYaraHeadless extends GhidraScript {
    public File csvFile;
    public PrintWriter csvPrintWriter;
    

    @Override
    protected void run() throws Exception {
        String [] args = getScriptArgs();

        csvFile = new File(args[0]);
        csvPrintWriter = new PrintWriter(csvFile);
        
        TaskMonitor monitor = new ConsoleTaskMonitor();


        // create a new property map to store various function hashes
        PropertyMapManager mapmgr = currentProgram.getUsrPropertyManager();
        ObjectPropertyMap fnhashobjmap;
        // check if properties exist already, or if need to create
        fnhashobjmap = mapmgr.getObjectPropertyMap("__CERT_Kaiju_FnHash");

        AddressIterator addriter = fnhashobjmap.getPropertyIterator();

        while(addriter.hasNext()){
            Address fn_addr = addriter.next();
            
            Class<?> c = null;
            try {
                c = Class.forName("ghidra.program.model.util.ObjectPropertyMap");
            } catch (ClassNotFoundException e) {
                // TODO
                StringWriter sw = new StringWriter();
                PrintWriter pw = new PrintWriter(sw);
                e.printStackTrace(pw);
                String sStackTrace = sw.toString(); // stack trace as a string
                print(sStackTrace);
                return;
            }

            FnHashSaveable prop = null;
            try
            {
                // the get() function was introduced in Ghidra 10.2
                fnhashobjmap.getClass().getDeclaredMethod("get", Address.class);
                try {
                    prop = (FnHashSaveable) fnhashobjmap.getClass().getDeclaredMethod("get", Address.class).invoke(fnhashobjmap, fn_addr);
                } catch (Exception e) {
                    // TODO
                    StringWriter sw = new StringWriter();
                    PrintWriter pw = new PrintWriter(sw);
                    e.printStackTrace(pw);
                    String sStackTrace = sw.toString(); // stack trace as a string
                    print(sStackTrace);
                    return;
                }
            } catch(NoSuchMethodException e) {
                // before Ghidra 10.2, it was getObject()
                try {
                    prop = (FnHashSaveable) fnhashobjmap.getClass().getDeclaredMethod("getObject").invoke(fnhashobjmap, fn_addr);
                } catch (Exception e2) {
                    // TODO
                    StringWriter sw = new StringWriter();
                    PrintWriter pw = new PrintWriter(sw);
                    e.printStackTrace(pw);
                    e2.printStackTrace(pw);
                    String sStackTrace = sw.toString(); // stack trace as a string
                    print(sStackTrace);
                    return;
                }
            }
            //FnHashSaveable prop = (FnHashSaveable) fnhashobjmap.getObject(fn_addr);
            
            String filename_value = currentProgram.getExecutablePath();
            
            String md5_value = currentProgram.getExecutableMD5();
            
            FnUtils fnu = null;
            try {
                fnu = new FnUtils(currentProgram.getFunctionManager().getFunctionAt(fn_addr), currentProgram, monitor);
            } catch (Exception e) {
                // TODO: can we do something better here?
                return;
            }
            List<byte[]> fnbytes_list = fnu.getPICBytesList();
            List<byte[]> fnmask_list = fnu.getPICMask();
            ByteArrayList arrayOfBytes = new ByteArrayList();
            ByteArrayList arrayOfMasks = new ByteArrayList();
            for (int j = 0; j < fnbytes_list.size(); ++j) {
                arrayOfBytes.add(fnbytes_list.get(j));
                arrayOfMasks.add(fnmask_list.get(j));
            }
            // the HexUtils.byteArrayToHexString function handles the YARA generation
            String bytes_value = HexUtils.byteArrayToHexString(arrayOfBytes.toArray(), " ", arrayOfMasks.toArray());
            
            String addr_value = fn_addr.toString();
            
            String pichash_value = prop.getPICHash();
            
            String numbytes_value = prop.getNumBytes().toString();
            
            String numinsns_value = prop.getNumInstructions().toString();
            
            // write values in YARA format
            writeYaraSignature(csvPrintWriter, filename_value, md5_value, bytes_value, addr_value, pichash_value, numbytes_value, numinsns_value, monitor);
            
            // two new lines to give a visual break
            writeNewLine(csvPrintWriter);
            writeNewLine(csvPrintWriter);
        }

        csvPrintWriter.flush();
        csvPrintWriter.close();
    }
    
    private static void writeNewLine(PrintWriter writer) {
        writer.print('\n');
    }

    /**
     * Write the given fileds into YARA format and save the result into
     * the file specified by the writer.
     */
    private final static void writeYaraSignature(PrintWriter writer, String filename_value, String md5_value, String bytes_value, String addr_value, String pichash_value, String numbytes_value, String numinsns_value, TaskMonitor monitor) {
        Calendar calendar = Calendar.getInstance();
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String todays_date = formatter.format(calendar.getTime());
    
        StringBuilder yarasig = new StringBuilder();
        /*
        rule Func_md5_[MD5]_[ADDR]
        {
        strings:
            // File [FILENAME] @ [ADDR] ([DATE])
            // string $md5_[MD5]_[ADDR] contains [B] bytes and [I] instructions
            $md5_[MD5]_[ADDR] = { [BYTES] }
        condition:
            all of them
        }   
        */
        yarasig.append(String.format("rule Func_md5_%1$s_%2$s\n", md5_value, addr_value));
        yarasig.append("{\n");
        yarasig.append("strings:\n");
        yarasig.append(String.format("\t// File '%1$s' @ %2$s (%3$s)\n", filename_value, addr_value, todays_date));
        yarasig.append(String.format("\t// PIC Hash %1$s\n", pichash_value));
        yarasig.append(String.format("\t// string $md5_%1$s_%2$s contains %3$s bytes and %4$s instructions\n", md5_value, addr_value, numbytes_value, numinsns_value));
        yarasig.append(String.format("\t$md5_%1$s_%2$s = { %3$s }\n", md5_value, addr_value, bytes_value));
        yarasig.append("condition:\n");
        yarasig.append("\tall of them\n");
        yarasig.append("}\n");
        writer.print(yarasig.toString());
    }

}
