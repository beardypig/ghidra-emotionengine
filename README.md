# ghidra-emotionengine
Ghidra Processor for the Play Station 2's Emotion Engine CPU.

The core MIPS/FPU/COP0 instruction are based off the MIPS32/64 processor included in Ghidra, with superfluous instructions stripped out and some instructions modified.

The following instuction sets are currently supported

 1. The core MIPS instruction set
 1. The EE core instruction set
 1. COP0 (System control processor) instruction set
 1. COP1 (FPU) instruction set
 1. COP2 (VU1) macro instruction set (WIP)

##Issues

I'm sure there are issues, and if you find any please report them.

##TODO

 - VU macro instruction set support
 - Function analysis
