![Dynamic YAML Badge](https://img.shields.io/badge/dynamic/yaml?url=https%3A%2F%2Fgithub.com%2FCERTCC%2Fkaiju%2Fraw%2Fmain%2F.github%2Fworkflows%2Frelease_on_tag.yml&query=%24.jobs.build_kaiju.strategy.matrix.ghidra_version&label=Supported%20Ghidra%20versions)
![release_on_tag Badge](https://github.com/CERTCC/kaiju/actions/workflows/release_on_tag.yml/badge.svg)
![run_tests_on_push_pr Badge](https://github.com/CERTCC/kaiju/actions/workflows/run_tests_on_push_pr.yml/badge.svg)

# CERT Kaiju Binary Analysis Framework for GHIDRA

CERT Kaiju is a collection of binary analysis tools for
[Ghidra](https://ghidra-sre.org).

This is a Ghidra/Java implementation of some features
of the [CERT Pharos Binary Analysis Framework][pharos], 
particularly the function hashing and malware analysis tools,
but is expected to grow new tools and capabilities over time.

As this is a new effort, this implementation does not yet have full
feature parity with the original C++ implementation based on ROSE;
however, the move to Java and Ghidra has actually enabled some new
features not available in the original framework -- notably, improved
handling of non-x86 architectures. Since some significant
re-architecting of the framework and tools is taking place, and the
move to Java and Ghidra enables different capabilities than the C++
implementation, the decision was made to utilize new branding
such that there would be less confusion between implementations
when discussing the different tools and capabilities.

Our intention for the near future is to maintain both the
original Pharos framework as well as Kaiju, side-by-side,
since both can provide unique features and capabilities.

CAVEAT: As a prototype, there are many issues that may come up when
evaluating the function hashes created by this plugin. For example,
unlike the Pharos implementation, Kaiju's function hashing module will
create hashes for very small functions (e.g., ones with a single
instruction like RET causing many more unintended collisions). As
such, analytical results may vary between this plugin and Pharos
fn2hash.

## Installation

[Pre-built Kaiju packages][prebuilts] are available. Simply download
the ZIP file corresponding with your version of Ghidra and install
according to the instructions below. It is recommended to install via
Ghidra's graphical interface, but it is also possible to manually
unzip into the appropriate directory to install.

CERT Kaiju requires the following runtime dependencies:
- [Ghidra](https://ghidra-sre.org) 10.3.x, 10.4.x, 11.0.x, 11.1.x, or 11.2
- JDK 21 (or 17 for older Ghidra releases)
- [Z3](https://github.com/Z3Prover/z3) including Z3 Java bindings .jar

Z3 is provided pre-compiled as part of the pre-built packages,
or you may build Z3 on your own or use your Linux distribution's package.

### Graphical Installation

Start Ghidra, and from the opening window, select from the menu:
`File > Install Extension`. Click the plus sign at the top of the
extensions window, navigate and select the .zip file in the file
browser and hit OK. The extension will be installed and a checkbox
will be marked next to the name of the extension in the window
to let you know it is installed and ready.

The interface will ask you to restart Ghidra to start using
the extension. Simply restart, and then Kaiju's extra features will
be available for use interactively or in scripts.

Some functionality may require enabling Kaiju plugins. To do this,
open the Code Browser then navigate to the menu `File > Configure`.
In the window that pops up, click the `Configure` link below
the "CERT Kaiju" category icon. A pop-up will display all available
publicly released Kaiju plugins. Check any plugins
you wish to activate, then hit OK. You will now have access to
interactive plugin features.

If a plugin is not immediately visible once enabled, you
can find the plugin underneath the `Window` menu in the Code Browser.

Experimental "alpha" versions of future tools may be available from
the "Experimental" category if you wish to test them. However
these plugins are definitely experimental and unsupported and not
recommended for production use. We do welcome early feedback though!

### Manual Installation

Ghidra extensions like Kaiju may also be installed manually
by unzipping the extension contents into the appropriate directory
of your Ghidra installation. For more information, please see
[The Ghidra Installation Guide](https://ghidra-sre.org/InstallationGuide.html#Extensions).

### Build It Yourself

You can also build the Kaiju extension directly from source code.
See the `INSTALL.md` file included in the top Kaiju source directory.

## Usage

Kaiju's tools may be used either in an interactive graphical way,
or via a "headless" mode more suited for batch jobs.
Some tools may only be available for graphical or headless use,
by the nature of the tool.

### Interactive Graphical Interface

Kaiju creates an interactive graphical interface (GUI) within Ghidra
utilizing Java Swing and Ghidra's plugin architecture.

Most of Kaiju's tools are actually Analysis plugins that run automatically
when the "Auto Analysis" option is chosen, either upon import of
a new executable to disassemble, or by directly choosing
`Analysis > Auto Analyze...` from the code browser window. You will
see several CERT Analysis plugins selected by default in the Auto Analyze
tool, but you can enable/disable any as desired.

The Analysis tools must be run before the various GUI tools will work,
however. In some corner cases, it may even be helpful to run the
Auto Analysis twice to ensure all of the metadata is produced
to create correct partitioning and disassembly information, which
in turn can influence the hashing results.

Analyzers are automatically run during Ghidra's analysis phase and include:
- **DisasmImprovements** = improves the function partitioning of the
  disassembly compared to the standard Ghidra partitioning.
- **Fn2Hash** = calculates function hashes for all functions in a program
  and is used to generate YARA signatures for programs.

The GUI tools include:
- **GhiHorn** = a plugin to calculate paths and reachability in
control flow graphs, utilizing Z3.
    - Select `Kaiju > GhiHorn` to access this tool from Ghidra's CodeBrowser.
      You can also launch the plugin by pressing `CTRL-G`.
- **Function Hash Viewer** = a plugin that displays an interactive list
of functions in a program and several types of hashes. Analysts can use this
to export one or more functions from a program into YARA signatures.
    - Select `Window > CERT Function Hash Viewer` from the menu to get started
    with this tool if it is not already visible. A new window will appear
    displaying a table of hashes and other data. Buttons along the top
    of the window can refresh the table or export data to file or
    a YARA signature. This window may also be docked into the main
    Ghidra CodeBrowser for easier use alongside other plugins.
    More extensive usage documentation can be found in
    Ghidra's `Help > Contents` menu when using the tool.
- **OOAnalyzer JSON Importer** = a plugin that can
load, parse, and apply Pharos-generated OOAnalyzer results to object
oriented C++ executables in a Ghidra project. When launched, the
plugin will prompt the user for the JSON output file produced by
OOAnalyzer that contains information about recovered C++
classes. After loading the JSON file, recovered C++ data types and
symbols found by OOAnalyzer are updated in the Ghidra Code
Browser. The plugin's design and implementation details are described
in our SEI blog post titled [Using OOAnalyzer to Reverse Engineer
Object Oriented Code with Ghidra][ooanalyzer-blog].
    - Select `Kaiju > OOAnalyzer Importer` from the menu to get started
    with this tool. A simple dialog popup will ask you to
    locate the JSON file you wish to import.
    More extensive usage documentation can be found in
    Ghidra's `Help > Contents` menu when using the tool.


### Command-line "Headless" Mode

Ghidra also supports a "headless" mode allowing tools to be run
in some circumstances without use of the interactive GUI.
These commands can therefore be utilized for scripting and
"batch mode" jobs of large numbers of files.

The headless tools largely rely on Ghidra's GhidraScript functionality.

Headless tools include:
- **fn2hash** = automatically run Fn2Hash on a given program
and export all the hashes to a CSV file specified
- **fn2yara** = automatically run Fn2Hash on a given program
and export all hash data as YARA signatures to the file specified
- **fnxrefs** = analyze a Program and export a list of Functions
based on entry point address that have cross-references in
data or other parts of the Program

A simple shell launch script named `kaijuRun` has been included to run
these headless commands for simple scenarios, such as outputing the
function hashes for every function in a single executable.
Assuming the `GHIDRA_INSTALL_DIR` variable is set, one might
for example run the launch script on a single executable as follows:

```
$GHIDRA_INSTALL_DIR/Ghidra/Extensions/kaiju/kaijuRun fn2hash example.exe
```

This command would output the results to an automatically named file as
`example.exe.Hashes.csv`.

Basic help for the `kaijuRun` script is available by running:

```
$GHIDRA_INSTALL_DIR/Ghidra/Extensions/kaiju/kaijuRun --help
```

Please see `docs/HeadlessKaiju.md` file in the repository
for more information on using this mode and
the `kaijuRun` launcher script.

### Further Documentation and Help

More comprehensive documentation and help is available, in one
of two formats.

See the `docs/` directory for Markdown-formatted documentation
and help for all Kaiju tools and components. These documents
are easy to maintain and edit and read even from a command line.

Alternatively, you may find the same documentation in Ghidra's
built-in help system. To access these help docs,
from the Ghidra menu, go to `Help > Contents`
and then select `CERT Kaiju` from the tree navigation on the
left-hand side of the help window.

Please note that the Ghidra Help documentation is the exact
same content as the Markdown files in the `docs/` directory;
thanks to an in-tree gradle plugin, gradle will automatically
parse the Markdown and export into Ghidra HTML during the build
process. This allows even simpler maintenance (update docs in
just one place, not two) and keeps the two in sync.

All new documentation should be added to the `docs/` directory.


## Licensing
    
This software is licensed under a simplified BSD-style license
by the Software Engineering Institute at Carnegie Mellon University.
Please find full details of this license, as well as licensing terms
of dependencies used in this project, in the `LICENSE.md` file
in the root of this repository.

The CERT Kaiju logo is based on [art][logo] created by Cameron Spahn,
originally released under terms of
[Creative Commons Attribution-Share Alike 4.0 International license][logo-license].


[pharos]: https://github.com/cmu-sei/pharos
[prebuilts]: https://github.com/certcc/kaiju/releases
[ooanalyzer-blog]: https://insights.sei.cmu.edu/sei_blog/2019/07/using-ooanalyzer-to-reverse-engineer-object-oriented-code-with-ghidra.html
[logo]: https://commons.wikimedia.org/wiki/File:RapatorCameronSpahn.jpg
[logo-license]: https://creativecommons.org/licenses/by-sa/4.0/
