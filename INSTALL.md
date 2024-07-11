INSTALL.md
----------

# Building and Installing Kaiju

Alternately to the pre-built packages, you may compile and build
Kaiju yourself.

## Build Dependencies

This release of CERT Kaiju supports Ghidra 10.3, 10.4, and 11,
and the following dependencies:

- [Ghidra](https://ghidra-sre.org) 10.3.x, 10.4.x, 11.0.x, 11.1.x
- [gradle](https://gradle.org/install/) 7.6+
- [GSON](https://github.com/google/gson) 2.8.6 (handled automatically by gradle)
- [JOpt Simple](https://github.com/jopt-simple/jopt-simple) 5.0.4 (handled automatically by gradle)
- Java 17+ (we recommend [OpenJDK 17](https://openjdk.java.net/install/))
- cmake, ninja, for building [Z3](https://github.com/Z3Prover/z3) 4.12.x with the Java API

**NOTE ABOUT GRADLE**: Please ensure that gradle is building against the same
JDK version in use by Ghidra on your system, or you may experience
installation problems. An internet connection while building using gradle
is highly recommended.

## Quick Build Instructions

In most cases, the following will build and run Kaiju in a few simple steps.
Use git clone to obtain the Kaiju source code, then from the top directory,
run the following commands:

```bash
gradle -PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra install dir>
gradle -PKAIJU_AUTOCATS_DIR=<path/to/autocats/dir> test
gradle -PKAIJU_AUTO_REMOVE install
```

Optionally: To make use of the `kaijuRun` script, be sure to set the script
with executable permission on Linux:
```bash
chmod u+x ${GHIDRA_INSTALL_DIR}/Ghidra/Extensions/kaiju/kaijuRun
```

Now run Ghidra like normal and enjoy working with Kaiju!

### Quick Build Tips

If you're planning to build, install, and test many times, you can skip
setting values like `GHIDRA_INSTALL_DIR` with a command line option by
instead placing it into a file named `gradle.properties` in the Kaiju
top source folder.

Create `gradle.properties` with the following content (substituting
the correct directory on your system):

```
GHIDRA_INSTALL_DIR=/path/to/ghidra
KAIJU_AUTOCATS_DIR=/path/to/autocats
KAIJU_AUTO_REMOVE=true
```

You can now run `gradle`, `gradle install` or `gradle test` without
needing to specify these options on the command line each time.

If you encounter any errors with this process, the following subsections
go into more detail about each step, possible errors, and tips on fixing.
If you still run into trouble, please file a ticket on our GitHub page
describing the errors you are encountering.

## Build Walkthrough and Tips

The following is a walkthrough of the quick build instructions,
to provide more details, commentary, and tips for addressing errors
or unusual build conditions. If the quick build instructions work
for you, then this section is not required.

### Step 1: Make sure you are connected to the internet

Gradle is configured to use a couple plugins and download some
dependencies. Ensure you are connected to the internet for best
experience!

Alternately, dependencies can be manually downloaded and placed
in the correct build locations. Please see the
Manually Handling Gradle Dependencies section below.

### Step 2: Building with Gradle

Gradle actually handles most of the build process in one step.
We make use of gradle-cmake to build Z3 automatically, then to build
the Kaiju extension against Ghidra.

```bash
gradle -PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra install dir>
```

This will take a while to build everything. The newly-built Kaiju
extension will appear as a .zip file within the `dist/` directory.
The filename will include "Kaiju", the version of Ghidra it was
built against, and the date it was built. If all goes well, you
should see a message like the following that tells you the name
of your built plugin.
```
Created ghidra_X.Y.Z_PUBLIC_YYYYMMDD_kaiju.zip in <path/to>/kaiju/dist
```
where `X.Y.Z` is the version of Ghidra you are using, and
`YYYYMMDD` is the date you built this Kaiju extension.

#### Manually Handling Gradle Dependencies

Gradle should be able to download a few Java dependencies, but in case
there is some issue with doing so, the following libraries can be
manually downloaded as .jar files and placed into the `/lib` directory
of the Kaiju source code to enable gradle building.

**NOTE ABOUT GSON**: In most cases, Gradle will automatically obtain this for
you.  If you find that you need to obtain it manually, you can download
[gson-2.8.6.jar](https://repo1.maven.org/maven2/com/google/code/gson/gson/2.8.6/gson-2.8.6.jar)
and place it in the `kaiju/lib` directory before building.

**NOTE ABOUT JOPT**: In most cases, Gradle will automatically obtain this for
you.  If you find that you need to obtain it manually, you can download
[jopt-simple-5.0.4.jar](https://repo1.maven.org/maven2/net/sf/jopt-simple/jopt-simple/5.0.4/jopt-simple-5.0.4.jar)
and place it in the `kaiju/lib` directory before building.

#### Building Z3 with Java bindings

Gradle normally handles building Z3 automatically, so you don't need
to change anything. But if you wanted to try a different version of Z3,
the following flags are used by our gradle build:

```bash
cmake \
  -DZ3_BUILD_LIBZ3_SHARED=true \
  -DZ3_USE_LIB_GMP=false \
  -DZ3_BUILD_JAVA_BINDINGS=true \
  -DZ3_INSTALL_JAVA_BINDINGS=true \
  -DZ3_JAVA_JAR_INSTALLDIR=%{_javadir} \
  -DZ3_JAVA_JNI_LIB_INSTALLDIRR=%{_jnidir} \
  -DZ3_ENABLE_EXAMPLE_TARGETS=false \
  -DZ3_LINK_TIME_OPTIMIZATION=true \
  -DCMAKE_BUILD_TYPE=Release
```

The extra `Z3_BUILD_JAVA_BINDINGS` flag ensures that the Java bindings are built
with the library. From here, install Z3 like normal; Java should
find the Z3 libraries on your system if they are installed to the usual directories.
Otherwise, we have to tell Java where to find Z3, as in the next build step.

1. Tips for installing [Z3 java bindings](https://github.com/Z3Prover/z3#java):
   1. You need to add the jar file (`com.microsoft.z3.jar`) to the `GhiHorn/lib`
      directory to make it available in the plugin.
      * On Windows, you can place this `.jar` file in the same directory as `ghidraRun.bat`
   2. You need to put the z3 and java binding libraries in a location that is available
      1. On MacOS these files are `libz3.dylib` and `libz3java.dylib`
      2. On linux these files are: `libz3.so` and `libz3java.so`
      3. On Windows, these files are `libz3.dll` and `libz3java.dll`

#### Optional: Running Tests With AUTOCATS

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

### Step 3: "Headless" Gradle-based Installation

Now that you have the built extension .zip file, it is possible
to install it into Ghidra from the graphical interface's
extension manager.

However, since you're already building it on the command line,
it may be slightly easier to install it directly from the command
line by using gradle:
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

### Troubleshooting

#### Fixing Z3 libraries not found

Once Kaiju is installed, Ghidra must be restarted (if you installed
via the graphical interface).

Kaiju attempts to autoload the Z3 native libraries based on your
operating system. The Status Check tool (at `Kaiju > Status Check`
in the main Ghidra window) will check if Z3 libraries are found
and loaded successfully. If you see a green check mark,
tools like GhiHorn that require Z3 should "just work".

However, if the libraries are not loaded properly, there are
a couple of ways to try to fix it.

**OPTION ONE**, if the autoload is unsuccessful (perhaps due to JVM
security, etc.), you can let Ghidra know to add the kaiju
library paths to the JVM runtime so they can be loaded.
To do this, you will need to MANUALLY make a small change to
the `ghidraRun` script of your Ghidra installation.
This is a completely Ghidra-supported step, not a "hack",
to allow custom configuration of the Java virtual machine
prior to running Ghidra.

Use your favorite text editor to open the `ghidraRun`
script in the top level directory of your Ghidra installation.
Then, in the script line under `# Launch Ghidra`, add the
following to the empty quotes:
```bash
-Djava.library.path=/path/to/Ghidra/Extensions/kaiju/os/<your_os_dir>
```
where `your_os_dir` is one of the following, depending
on the architecture you are running:
* `linux_x86_64` (Linux distributions)
* `mac_x86_64` (Mac iOS)
* `win_x86_64` (Windows 10+)

As an example, on a typical 64-bit linux OS, the script should
after editing look similar to:
```bash
# Launch Ghidra
"${SCRIPT_DIR}"/support/launch.sh bg Ghidra "${MAXMEM}" "-Djava.library.path=/path/to/Ghidra/Extensions/kaiju/os/linux_x86_64" ghidra.GhidraRun "$@"
```

Once this edit is made, save and close your text editor.

You can now run Ghidra like normal by running `ghidraRun`.
This ensures the Z3 libraries are properly loaded.

You only need to make this change once, when first installing
the extension; from now on, all future Ghidra runs will
including this library path and load the Z3 libraries.
If you install a new Ghidra version, you will need to repeat
this process along with re-installing Kaiju.

**OPTION TWO**: Particularly on Linux, the included prebuilt
Z3 libraries are built for the latest Ubuntu LTS release.
The libraries may not run properly on other distributions.
You may however be able to install Z3 libraries directly
from your distrubtion's package manager, and Java will load
them since they are in system library paths like `/usr/lib`.
In this case, updating the `ghidraRun` script may not be
necessary -- but also,
the system packages may be a different version of Z3 than
supported by Kaiju. Therefore, certain Kaiju tools like GhiHorn
may not work properly and we cannot promise being able
to support or help with troubleshooting.

**OPTION THREE**: If you want to ensure the same version of Z3
we develop with, you can manually build Z3 for your particular
platform/operating system/distribution. The Gradle build system
can automatically build Z3 for your system if you build Kaiju
from source; otherwise, build Z3 separately according to the Z3
docs and then drop the built Z3 libraries into an appropriate
system directory (or the os directory in Kaiju if you want to try).
      

