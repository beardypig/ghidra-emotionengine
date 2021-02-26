# ghidra-emotionengine [![run tests](https://github.com/beardypig/ghidra-emotionengine/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/beardypig/ghidra-emotionengine/actions/workflows/test.yml)
Ghidra Processor for the Play Station 2's Emotion Engine CPU.

The core MIPS/FPU/COP0 instruction are based off the MIPS32/64 processor included in Ghidra, with superfluous instructions stripped out and some instructions modified.

The following instuction sets are currently supported

 1. The core MIPS instruction set
 1. The EE core instruction set
 1. COP0 (System control processor) instruction set
 1. COP1 (FPU) instruction set
 1. COP2 (VU0) macro instruction set

## Compilation

If you want to build the extension yourself, install `gradle` and run
 
```
gradle -PGHIDRA_INSTALL_DIR=/path/to/ghidra buildExtension
```

Only Ghidra versions 9.2 and above are supported.

## Installation

Precompiled packages for each version of Ghidra are available in the [releases](https://github.com/beardypig/ghidra-emotionengine/releases) tab. To install the package, follow the instructions in the [Ghidra docs](https://ghidra-sre.org/InstallationGuide.html#Extensions).
A "nightly" version of the plugin is available under the [latest](https://github.com/beardypig/ghidra-emotionengine/releases/tag/latest) tag. This version is updated once per day. 

## Issues

I'm sure there are issues, and if you find any please report them.

## TODO

 - Function analysis
