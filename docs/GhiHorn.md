# GhiHorn
A horn encoder for Ghidra version 10.1+ and above.
GhiHorn uses Z3 SMT library.

## Old Z3 Installation

These instructions are outdated; see `INSTALL.md` in the Kaiju
source code for updated information. These directions are
preserved until confirmed that we have a better automated way
to install Z3.

1. You need to install Z3 and the [Z3 java bindings](https://github.com/Z3Prover/z3#java)
   1. You need to add the jar file (`com.microsoft.z3.jar`) to the `GhiHorn/lib`
      directory to make it available in the plugin.
      Alternately, set the `Z3CLASSPATH` environment variable to the path to your
      jar file as project variable for gradle. (This can help if using pre-built
      packages e.g. on linux, just point to the system directory.)
   2. You need to put the z3 and java binding libraries in a location that is available
      1. On MacOS these files are `libz3.dylib` and `libz3java.dylib`
      2. On linux these files are: `libz3.so` and `libz3java.so`
2. Build the GhiHorn plugin. The plugin build process uses `gradle` with some additions:
      * Run `gradle` to build the plugin
      * Rung `gradle install` to build the distribution package and copy it to Ghidra 
        * Be sure to set your _GHIDRA_INSTALL_DIR_ to your ghidra installation
          in the file _gradle.properties_ before attempting to build.
3. Following step 2, the plugin should be installed. You may need to restart
   Ghidra to make the plugin available.
4. You can launch the plugin by pressing `CTRL-G` or selecting GhiHorn from the
   CERT menu.
