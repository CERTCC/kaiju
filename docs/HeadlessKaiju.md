# Using CERT Kaiju in "Headless" Mode

## Overview

The following Kaiju tools are available in "headless" mode:

- **ghihorn** = calculate paths in a given program
- **fn2hash** = automatically run Fn2Hash on a given program
and export all the hashes to a CSV file specified
- **fn2yara** = automatically run Fn2Hash on a given program
and export all hash data as YARA signatures to the file specified
- **fnxrefs** = analyze a Program and export a list of Functions
based on entry point address that have cross-references in
data or other parts of the Program

These tools are designed to work completely from the command line;
the user does not need to run the GUI version of Ghidra to utilize
this mode. This may be helpful in several scenarios, such as
an automated "batch" mode where a script runs Ghidra/Kaiju tools
automatically on a batch of samples, or to allow remote analysis
on a virtual machine/resources with only a remote terminal.

*NOTE*: These tools may not completely correspond with features available
in graphical interface tools, simply due to the nature of
how a typical user utilizes GUI versus command line tools.

## Using the `runKaiju` script

In the top installation directory of the Kaiju extension is a script called `runKaiju`.

This script is the easiest way to run Kaiju tools from a command line,
at least on a Linux distribution.

Run:
```
kaijuRun --help
```
to get more information about how to use the headless command line features of
Ghidra and Kaiju from a more friendly interface.

You may need to first set executable permissions on the script.

Under the hood, `kaijuRun` runs the Ghidra headless analyzer, which you can also
run directly especially if you are using Windows. Some tips on how to run the
Ghidra headless analyzer directly with Kaiju scripts are included below.

## Using the Ghidra Headless Analyzer

Kaiju makes use of Ghidra's built-in "Headless Analyzer" mode, as well
as some GhidraScripts, to expose functionality and tools to the command line.
Users are recommended to familiar with the official Ghidra documentation,
for details please see the [Ghidra Headless Analyzer README](https://ghidra.re/ghidra_docs/analyzeHeadlessREADME.html).

A brief overview, for the purposes of using the CERT Kaiju Function Hashing plugin in a headless mode, is provided here.

---
The general syntax for the Headless analyzer is:

`analyzeHeadless PROJECT_DIRECTORY PROJECT_NAME [options...]`

When using the Kaiju Function Hashing plugin there are two steps that need to be accomplished in addition to the usual import and analyze steps:

- enabling the Kaiju Function Hashing plugin before analysis (using the `-preScript` option)
- extracting the function hashing artifacts after analysis (using the `-postScript` option)

We have provided scripts to perform these actions including:

- _KaijuSetupScript.java_  
Ensures that the Kaiju Function Hashing plugin is enabled for headless analysis.

- _KaijuExportCSVHeadless.java_  
Extracts the function hashing artifacts and outputs them to the specified file in CSV format.

- _KaijuExportYaraHeadless.java_  
Extracts the function hashing artifacts and outputs them to the specified file as YARA rules.

- _GhihornHeadlessTool.java_  
Runs Ghihorn and outputs results to a file.

---

### Examples 

Analyzing a single binary and outputting function hashes in a CSV file:  
`$GHIDRA_INSTALL_DIR/support/analyzeHeadless $HOME/ghidra_projects tmpProj -import exampleFile.exe -preScript KaijuSetupScript.java -postScript KaijuExportCSVHeadless.java exampleFileResults.csv`

Analyzing a directory of binaries and outputting all function hashes:  
`$GHIDRA_INSTALL_DIR/support/analyzeHeadless $HOME/ghidra_projects tmpProj -import path/to/binaries -preScript KaijuSetupScript.java -postScript KaijuExportCSVHeadless.java exampleFileResults.csv`


Using `-okToDelete` and `-deleteProject` options on analyzeHeadless to remove tmpProj after import:  
`$GHIDRA_INSTALL_DIR/support/analyzeHeadless $HOME/ghidra_projects tmpProj -okToDelete -deleteProject -import exampleFile.exe -preScript KaijuSetupScript.java -postScript KaijuExportCSVHeadless.java exampleFileResults.csv`

*** NOTE *** This will DELETE any Ghidra project named `tmpProj` in your user directory defined by `$HOME/ghidra_projects` (or throw an error if `$HOME` is undefined)!

