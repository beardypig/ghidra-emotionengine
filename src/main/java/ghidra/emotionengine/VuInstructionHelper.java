package ghidra.emotionengine;

import static java.math.BigInteger.ONE;

import ghidra.program.model.lang.ParallelInstructionLanguageHelper;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.ProgramContext;

public class VuInstructionHelper implements ParallelInstructionLanguageHelper {

    private static final String TAB = "\t";
    private static final String MICRO_MODE_REG = "microMode";

    @Override
    public String getMnemonicPrefix(Instruction instr) {
        return TAB;
    }

    @Override
    public boolean isParallelInstruction(Instruction instruction) {
        if (instruction.getLength() > 4) {
            return false;
        }
        ProgramContext pc = instruction.getProgram().getProgramContext();
        Register context = pc.getRegister(MICRO_MODE_REG);
        RegisterValue contextValue = pc.getRegisterValue(context, instruction.getAddress());
        return contextValue.getUnsignedValueIgnoreMask().equals(ONE);
    }

    @Override
    public boolean isEndOfParallelInstructionGroup(Instruction instruction) {
        return instruction.getAddress().getOffset() % 8 == 4;
    }

}
