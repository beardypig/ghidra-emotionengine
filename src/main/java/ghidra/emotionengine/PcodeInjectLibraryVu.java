package ghidra.emotionengine;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.template.OpTpl;
import ghidra.pcodeCPort.slgh_compile.PcodeParser;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.InjectPayloadSleigh;
import ghidra.program.model.lang.PcodeInjectLibrary;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import org.jdom.JDOMException;

public class PcodeInjectLibraryVu extends PcodeInjectLibrary {

    private PcodeParser parser;
    private SleighLanguage language;

    // vector
    protected static final String VABS = "VABS";
    protected static final String VADD = "VADD";
    protected static final String VADDBC = "VADDBC";
    protected static final String VMADD = "VMADD";
    protected static final String VMADDBC = "VMADDBC";
    protected static final String VSUB = "VSUB";
    protected static final String VSUBBC = "VSUBBC";
    protected static final String VMSUB = "VMSUB";
    protected static final String VMSUBBC = "VMSUBBC";
    protected static final String VMUL = "VMUL";
    protected static final String VMULBC = "VMULBC";
    protected static final String VFTOI = "VFTOI";
    protected static final String VITOF = "VITOF";
    protected static final String VULQ = "VULQ";
    protected static final String VUSQ = "VUSQ";
    protected static final String VMAX = "VMAX";
    protected static final String VMAXBC = "VMAXBC";
    protected static final String VMIN = "VMINI";
    protected static final String VMINBC = "VMINIBC";
    protected static final String VMFIR = "VMFIR";
    protected static final String VMOVE = "VMOVE";
    protected static final String VMOVEBC = "VMOVEBC";
    protected static final String VMR32 = "VMR32";
    protected static final String VCLEAR = "VCLEAR";

    protected static final Set<String> VECTOR_INSTRUCTIONS = getVectorInstructions();

    public PcodeInjectLibraryVu(SleighLanguage l) {
        super(l);
        language = l;
        String translateSpec = l.buildTranslatorTag(l.getAddressFactory(),
			getUniqueBase(), l.getSymbolTable());
		parser = null;
		try {
			parser = new PcodeParser(translateSpec);
		}
		catch (JDOMException e1) {
			Msg.error(this, e1);
		}
    }

    static Set<String> getVectorInstructions() {
        Set<String> instructions = new HashSet<>();
        instructions.add(VABS);
        instructions.add(VADD);
        instructions.add(VADDBC);
        instructions.add(VMADD);
        instructions.add(VMADDBC);
        instructions.add(VFTOI);
        instructions.add(VITOF);
        instructions.add(VSUB);
        instructions.add(VSUBBC);
        instructions.add(VMSUB);
        instructions.add(VMSUBBC);
        instructions.add(VMUL);
        instructions.add(VMULBC);
        instructions.add(VULQ);
        instructions.add(VUSQ);
        instructions.add(VMAX);
        instructions.add(VMAXBC);
        instructions.add(VMIN);
        instructions.add(VMINBC);
        instructions.add(VMFIR);
        instructions.add(VMOVE);
        instructions.add(VMOVEBC);
        instructions.add(VMR32);
        instructions.add(VCLEAR);
        return Collections.unmodifiableSet(instructions);
    }

    @Override
	protected InjectPayloadSleigh allocateInject(String sourceName, String name, int tp) {
		if (tp != InjectPayload.CALLOTHERFIXUP_TYPE) {
			return super.allocateInject(sourceName, name, tp);
		}
        if (VECTOR_INSTRUCTIONS.contains(name)) {
            return new InjectPayloadVu(sourceName, language);
        }
		return super.allocateInject(sourceName, name, InjectPayload.CALLOTHERFIXUP_TYPE);
    }

    @Override
	/**
	* This method is called by DecompileCallback.getPcodeInject.
	*/
	public InjectPayload getPayload(int type, String name, Program program, String context) {
		if (!VECTOR_INSTRUCTIONS.contains(name)) {
			return super.getPayload(type, name, program, context);
		}

		InjectPayloadVu payload =
			(InjectPayloadVu) super.getPayload(InjectPayload.CALLOTHERFIXUP_TYPE, name, program,
				context);

		synchronized (parser) {
            try {
                OpTpl[] opTemplates = payload.getPcode(parser, program, context);
                adjustUniqueBase(opTemplates);
            } finally {
                //clear the added symbols so that the parser can be used again without
                //duplicate symbol name conflicts.
                parser.clearSymbols();
            }
		}
		return payload;
	}
}
