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

## Quick Installation

[Pre-built Kaiju packages][prebuilts] are available. Simply download
the ZIP file corresponding with your version of Ghidra and install
according to the instructions below. It is recommended to install via
Ghidra's graphical interface, but it is also possible to manually
unzip into the appropriate directory to install.

CERT Kaiju requires the following runtime dependencies:
- [Ghidra](https://ghidra-sre.org) 10.1+
- Java 11+ (we recommend [OpenJDK 11](https://openjdk.java.net/install/))
- [Z3](https://github.com/Z3Prover/z3) including Z3 Java bindings .jar

**NOTE**: We strongly recommend updating to Ghidra 10.1.2 or above
in order to address the log4j vulnerability that exists
in the library bundled with older versions of Ghidra.

**NOTE**: If you use Linux, installing your distribution's Z3 packages
may be sufficient. Otherwise, or if you are using Windows or Mac,
you will need to manually add the Z3 Java bindings to the correct
location in order to use some tools like Ghihorn. Please see
the "Installation" section underneath "Ghihorn" later in this README.

**NOTE**: It is also possible to build the extension package
on your own and install it. Please see the instructions
under the "Build Kaiju Yourself" section below.

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

### GhiHorn
A horn encoder for Ghidra version 10.1+.

#### Installation

1. You need to install Z3 and the [Z3 java bindings](https://github.com/Z3Prover/z3#java)
   1. You need to add the jar file (`com.microsoft.z3.jar`) to the `GhiHorn/lib`
      directory to make it available in the plugin.
      * On Windows, you can place this `.jar` file in the same directory as `ghidraRun.bat`
   2. You need to put the z3 and java binding libraries in a location that is available
      1. On MacOS these files are `libz3.dylib` and `libz3java.dylib`
      2. On linux these files are: `libz3.so` and `libz3java.so`
      3. On Windows, these files are `libz3.dll` and `libz3java.dll`
2. Build the GHiHorn plugin. The plugin build process uses `gradle` with some addtions:
      * Run `gradle` to build the plugin
      * Rung `gradle install` to build the ditribution package and copy it to Ghidra
        * Be sure to set your _GHIDRA_INSTALL_DIR_ to your ghidra installation
          in the file _gradle.properties_ before attempting to build.
3. Following step 2, the plugin should be installed. You may need to restart
   Ghidra to make the plugin available.
4. You can launch the plugin by pressing `CTRL-G` or selecting GhiHorn from the
   CERT menu.


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


## Building Kaiju Yourself Using Gradle

Alternately to the pre-built packages, you may compile and build
Kaiju yourself.

### Build Dependencies

CERT Kaiju requires the following build dependencies:
- [Ghidra](https://ghidra-sre.org) 10.1+
- [gradle](https://gradle.org/install/) 6.9+ or 7+
- [GSON](https://github.com/google/gson) 2.8.6 (handled automatically by gradle)
- [JOpt Simple](https://github.com/jopt-simple/jopt-simple) 5.0.4 (handled automatically by gradle)
- [Z3](https://github.com/Z3Prover/z3) 4.8.11+, built with the Java API
- Java 11+ (we recommend [OpenJDK 11](https://openjdk.java.net/install/))

**NOTE ABOUT GRADLE**: Please ensure that gradle is building against the same
JDK version in use by Ghidra on your system, or you may experience
installation problems.

**NOTE ABOUT GSON**: In most cases, Gradle will automatically obtain this for
you.  If you find that you need to obtain it manually, you can download
[gson-2.8.6.jar](https://repo1.maven.org/maven2/com/google/code/gson/gson/2.8.6/gson-2.8.6.jar)
and place it in the `kaiju/lib` directory before building.

**NOTE ABOUT JOPT**: In most cases, Gradle will automatically obtain this for
you.  If you find that you need to obtain it manually, you can download
[jopt-simple-5.0.4.jar](https://repo1.maven.org/maven2/net/sf/jopt-simple/jopt-simple/5.0.4/jopt-simple-5.0.4.jar)
and place it in the `kaiju/lib` directory before building.

### Build Instructions

#### Building Z3 with Java bindings

If you use linux, your distro may provide Java bindings.
If not, you will need to build Z3 with the appropriate findings:
```bash
cmake \
  -DZ3_BUILD_LIBZ3_SHARED=true \
  -DZ3_USE_LIB_GMP=true \
  -DZ3_BUILD_JAVA_BINDINGS=true \
  -DZ3_INSTALL_JAVA_BINDINGS=true \
  -DZ3_JAVA_JAR_INSTALLDIR=%{_javadir} \
  -DZ3_JAVA_JNI_LIB_INSTALLDIRR=%{_jnidir} \
  -DZ3_ENABLE_EXAMPLE_TARGETS=false \
  -DZ3_LINK_TIME_OPTIMIZATION=true \
  -DCMAKE_BUILD_TYPE=Release
```

The extra `Z3_BUILD_JAVA_BINDINGS` flag ensures that the Java bindings are built
with the library. From here, install Z3 like normal.

#### Building Kaiju

Once dependencies are installed, Kaiju may be built as a Ghidra
extension by using the `gradle` build tool. It is recommended to
first set a Ghidra environment variable, as Ghidra installation
instructions specify. You will also need to identify where to find
your local build of Z3's Java API .jar.

In short: set `GHIDRA_INSTALL_DIR`and `Z3CLASSPATH` as environment
variables first, then run `gradle` without any options:
```bash
export GHIDRA_INSTALL_DIR=<Absolute path to Ghidra install dir>
export Z3CLASSPATH=<Absolute path to dir with Z3 .jar file>
gradle
```

NOTE: Your Ghidra install directory is the directory containing
the `ghidraRun` script (the top level directory after unzipping
the Ghidra release distribution into the location of your choice.)

If for some reason your environment variable is not or can not be set,
you can also specify it on the command like with:
```bash
gradle -PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra install dir> -PZ3CLASSPATH=<Absolute path to dir with Z3 .jar file>
```

In either case, the newly-built Kaiju extension will appear as a
.zip file within the `dist/` directory. The filename will include
"Kaiju", the version of Ghidra it was built against, and the date
it was built. If all goes well, you should see a message like the
following that tells you the name of your built plugin.
```
Created ghidra_X.Y.Z_PUBLIC_YYYYMMDD_kaiju.zip in <path/to>/kaiju/dist
```
where `X.Y.Z` is the version of Ghidra you are using, and
`YYYYMMDD` is the date you built this Kaiju extension.

### Optional: Running Tests With AUTOCATS

While not required, you may want to use the Kaiju testing suite to
verify proper compilation and ensure there are no regressions
while testing new code or before you install Kaiju in a production
environment.

In order to run the Kaiju testing suite, you will need to first obtain
the AUTOCATS (AUTOmated Code Analysis Testing Suite). AUTOCATS contains
a number of executables and related data to perform tests and check
for regressions in Kaiju. These test cases are shared with the Pharos
binary analysis framework, therefore AUTOCATS is located in a separate
git repository.

Clone the AUTOCATS repository with:
```
git clone https://github.com/cmu-sei/autocats
```

We recommend cloning the AUTOCATS repository into the same parent
directory that holds Kaiju, but you may clone it anywhere you wish.

The tests can then be run with:

```
gradle -PKAIJU_AUTOCATS_DIR=path/to/autocats/dir test
```
where of course the correct path is provided to your cloned
AUTOCATS repository directory. If cloned to the same parent
directory as Kaiju as recommended, the command would look like:
```
gradle -PKAIJU_AUTOCATS_DIR=../autocats test
```

The tests cannot be run without
providing this path; if you do forget it, gradle will abort
and give an error message about providing this path.

Kaiju has a dependency on [JUnit 5](https://junit.org/junit5/)
only for running tests. Gradle should automatically retrieve
and use JUnit, but you may also download JUnit and manually place
into `lib/` directory of Kaiju if needed.

You will want to run the update command whenever you pull the
latest Kaiju source code, to ensure they stay in sync.

### First-Time "Headless" Gradle-based Installation

If you compiled and built your own Kaiju extension,
you may alternately install the extension directly on the command line via
use of gradle. Be sure to set `GHIDRA_INSTALL_DIR` as an environment
variable first (if you built Kaiju too, then you should already have
this defined), then run `gradle` as follows:
```bash
export GHIDRA_INSTALL_DIR=<Absolute path to Ghidra install dir>
gradle install
```
or if you are unsure if the environment variable is set,
```bash
gradle -PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra install dir> install
```

Extension files should be copied automatically. Kaiju will be available
for use after Ghidra is restarted.

**NOTE**: Be sure that Ghidra is NOT running before using gradle to
install. We are aware of instances when the caching does not appear
to update properly if installed while Ghidra is running, leading to
some odd bugs. If this happens to you, simply exit Ghidra and try
reinstalling again.

#### Consider Removing Your Old Installation First

It might be helpful to first completely remove any older install of
Kaiju before updating to a newer release. We've seen some cases
where older versions of Kaiju files get stuck in the cache and
cause interesting bugs due to the conflicts. By removing the old
install first, you'll ensure a clean re-install and easy use.

The gradle build process now can auto-remove previous installs of Kaiju
if you enable this feature. To enable the autoremove,
add the "KAIJU_AUTO_REMOVE" property to your install command, such as
(assuming the environment variable is probably set as in previous section):
```bash
gradle -PKAIJU_AUTO_REMOVE install
```

If you'd prefer to remove your old installation manually, perform a command like:
```bash
rm -rf $GHIDRA_INSTALL_DIR/Extensions/Ghidra/*kaiju*.zip $GHIDRA_INSTALL_DIR/Ghidra/Extensions/kaiju
```


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
