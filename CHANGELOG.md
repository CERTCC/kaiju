# Current Release

## 250610
- Improvements:
* kaijuRun script now uses unique temporary directories to prevent conflicts
* Added automatic cleanup of temporary directories on kaijuRun exit

## 250417
- Improvements:
* Support for Ghidra 11.3.2

## 250220
- Improvements:
* Support for Ghidra 11.3.1

## 250110

- Improvements:
* Support for Ghidra 11.3

## 241204
- Improvements:
* Include Z3 for ARM Macs
* Stream-line build system a bit

## 241119
- Bugfixes:
* Fix bad performance of Disassembly Improvements in specific situations (#81)
- Improvements:
* Use "CERT Kaiju" more consistently
* Enable Disassembly Improvements for x86-64

## 241107
- Improvements:
* Support for Ghidra 11.2.1

## 240930
- Improvements:
* Support for Ghidra 11.2

## 240711
- Improvements:
* Support for Ghidra 11.1.1 and 11.1.2

## 240610
- Improvements:
* Support for Ghidra 11.1

## 240411
- Improvements:
* Support for Ghidra 11.0.3

## 240328
- Improvements:
* Support for Ghidra 11.0.2

## 240220
- Improvements:
* Support for Ghidra 11.0.1

## 240106
- Bugfixes:
* Improve performance of Disassembly Improvements (#65)

## 231227
- Improvements:
* Support for Ghidra 11.0

## 231204:
- Bugfixes:
* Fix OptionsService for older versions of Ghidra (#58)

## 231201

- Improvements:
* Improve HighCfg entry node heuristic
* Add additional logging when failing to create decompiler
* Ensure that start and goal addresses are valid instructions

## 231003

- Improvements:
* Add support for Ghidra 10.4

## 230921

- Bugfixes:
* Fix packaged extensions so they can use the included z3 libraries
* Add workaround for when HighCFG entry vertex is incorrectly identified (Fix #40)
* Add workaround for #38, where an Indirect pcode op causes an exception

- Improvements:
* Improve UI responsiveness during DisasmImprovements
* Avoid relinking z3 when rebuilding with gradle

## 230921

- Updated to build extensions for Ghidra 10.3.1, 10.3.2, 10.3.3

# Past Releases

## 230518

- New Features:
  * Updated to require Ghidra 10.3+ due to API changes

## 230406

- Bugfixes:
  * Includes a small patch to print better debugging information, to help address #38

## 230330

- New Features:
  * Updated gradle to allow auto building Z3 from downloaded source zip
  * Gradle build to support Java 17 for Ghidra 10.2+
  * Simplified build and install instructions, in new INSTALL.md file
  * Status check tool to test for Z3, autoload library if possible
- Bugfixes:
  * Fix an FnHash error that would hang the UI (#25)
  * Fix errors loading Z3 libraries (#6, #20, #30)
  * Catch GhiHorn error from Ghidra HighVariable (#23)
  * Catch an error with java time (#34)
