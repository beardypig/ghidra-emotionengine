package ghidra.emotionengine;

import java.util.function.Function;

import org.junit.Test;


public class InjectPayloadVuTest {

	private class InjectPayloadVuTester extends InjectPayloadVu {

		private static final int DEST = 13;

		private InjectPayloadVuTester(String name) {
			super(null, null);
			this.name = name;
			this.dest = DEST;
		}

	}

	private String runOpCode(String name) {
		InjectPayloadVuTester currentTest = new InjectPayloadVuTester(name);
		Function<InjectPayloadVu, String> function = currentTest.getInstruction();
		return function.apply(currentTest);
	}

	@Test
	public void opcodeVABS() {
		assert runOpCode(PcodeInjectLibraryVu.VABS).equals("VUFT[0,32] = abs(VUFS[0,32]);\nVUFT[32,32] = abs(VUFS[32,32]);\nVUFT[96,32] = abs(VUFS[96,32]);\n");
	}

	@Test
	public void opcodeVADD() {
		assert runOpCode(PcodeInjectLibraryVu.VADD).equals("VUFD[0,32] = VUFS[0,32] f+ VUFT[0,32];\nvuMAC_32[3,1] = (VUFD[0,32] == 0);\nvuMAC_32[7,1] = (VUFD[0,32] < 0);\nvuMAC_32[11,1] = 0;\nvuMAC_32[15,1] = nan(VUFD[0,32]);\nVUFD[32,32] = VUFS[32,32] f+ VUFT[32,32];\nvuMAC_32[2,1] = (VUFD[32,32] == 0);\nvuMAC_32[6,1] = (VUFD[32,32] < 0);\nvuMAC_32[10,1] = 0;\nvuMAC_32[14,1] = nan(VUFD[32,32]);\nvuMAC_32[1,1] = 0;\nvuMAC_32[5,1] = 0;\nvuMAC_32[9,1] = 0;\nvuMAC_32[13,1] = 0;\nVUFD[96,32] = VUFS[96,32] f+ VUFT[96,32];\nvuMAC_32[0,1] = (VUFD[96,32] == 0);\nvuMAC_32[4,1] = (VUFD[96,32] < 0);\nvuMAC_32[8,1] = 0;\nvuMAC_32[12,1] = nan(VUFD[96,32]);\nvuStatus_32[0,1] = vuMAC_32[0,1] || vuMAC_32[1,1] || vuMAC_32[2,1] || vuMAC_32[3,1];\nvuStatus_32[1,1] = vuMAC_32[4,1] || vuMAC_32[5,1] || vuMAC_32[6,1] || vuMAC_32[7,1];\nvuStatus_32[2,1] = vuMAC_32[8,1] || vuMAC_32[9,1] || vuMAC_32[10,1] || vuMAC_32[11,1];\nvuStatus_32[3,1] = vuMAC_32[12,1] || vuMAC_32[13,1] || vuMAC_32[14,1] || vuMAC_32[15,1];\nvuStatus_32[6,1] = vuStatus_32[6,1] || vuStatus_32[0,1];\nvuStatus_32[7,1] = vuStatus_32[7,1] || vuStatus_32[1,1];\nvuStatus_32[8,1] = vuStatus_32[8,1] || vuStatus_32[2,1];\nvuStatus_32[9,1] = vuStatus_32[9,1] || vuStatus_32[3,1];\n");
	}

	@Test
	public void opcodeVADDBC() {
		assert runOpCode(PcodeInjectLibraryVu.VADDBC).equals("VUFD[0,32] = VUFS[0,32] f+ VUFT;\nvuMAC_32[3,1] = (VUFD[0,32] == 0);\nvuMAC_32[7,1] = (VUFD[0,32] < 0);\nvuMAC_32[11,1] = 0;\nvuMAC_32[15,1] = nan(VUFD[0,32]);\nVUFD[32,32] = VUFS[32,32] f+ VUFT;\nvuMAC_32[2,1] = (VUFD[32,32] == 0);\nvuMAC_32[6,1] = (VUFD[32,32] < 0);\nvuMAC_32[10,1] = 0;\nvuMAC_32[14,1] = nan(VUFD[32,32]);\nvuMAC_32[1,1] = 0;\nvuMAC_32[5,1] = 0;\nvuMAC_32[9,1] = 0;\nvuMAC_32[13,1] = 0;\nVUFD[96,32] = VUFS[96,32] f+ VUFT;\nvuMAC_32[0,1] = (VUFD[96,32] == 0);\nvuMAC_32[4,1] = (VUFD[96,32] < 0);\nvuMAC_32[8,1] = 0;\nvuMAC_32[12,1] = nan(VUFD[96,32]);\nvuStatus_32[0,1] = vuMAC_32[0,1] || vuMAC_32[1,1] || vuMAC_32[2,1] || vuMAC_32[3,1];\nvuStatus_32[1,1] = vuMAC_32[4,1] || vuMAC_32[5,1] || vuMAC_32[6,1] || vuMAC_32[7,1];\nvuStatus_32[2,1] = vuMAC_32[8,1] || vuMAC_32[9,1] || vuMAC_32[10,1] || vuMAC_32[11,1];\nvuStatus_32[3,1] = vuMAC_32[12,1] || vuMAC_32[13,1] || vuMAC_32[14,1] || vuMAC_32[15,1];\nvuStatus_32[6,1] = vuStatus_32[6,1] || vuStatus_32[0,1];\nvuStatus_32[7,1] = vuStatus_32[7,1] || vuStatus_32[1,1];\nvuStatus_32[8,1] = vuStatus_32[8,1] || vuStatus_32[2,1];\nvuStatus_32[9,1] = vuStatus_32[9,1] || vuStatus_32[3,1];\n");
	}

	@Test
	public void opcodeVMADD() {
		assert runOpCode(PcodeInjectLibraryVu.VMADD).equals("VUFD[0,32] = vuACC[0,32] f+ VUFS[0,32] f* VUFT[0,32];\nvuMAC_32[3,1] = (VUFD[0,32] == 0);\nvuMAC_32[7,1] = (VUFD[0,32] < 0);\nvuMAC_32[11,1] = 0;\nvuMAC_32[15,1] = nan(VUFD[0,32]);\nVUFD[32,32] = vuACC[32,32] f+ VUFS[32,32] f* VUFT[32,32];\nvuMAC_32[2,1] = (VUFD[32,32] == 0);\nvuMAC_32[6,1] = (VUFD[32,32] < 0);\nvuMAC_32[10,1] = 0;\nvuMAC_32[14,1] = nan(VUFD[32,32]);\nvuMAC_32[1,1] = 0;\nvuMAC_32[5,1] = 0;\nvuMAC_32[9,1] = 0;\nvuMAC_32[13,1] = 0;\nVUFD[96,32] = vuACC[96,32] f+ VUFS[96,32] f* VUFT[96,32];\nvuMAC_32[0,1] = (VUFD[96,32] == 0);\nvuMAC_32[4,1] = (VUFD[96,32] < 0);\nvuMAC_32[8,1] = 0;\nvuMAC_32[12,1] = nan(VUFD[96,32]);\nvuStatus_32[0,1] = vuMAC_32[0,1] || vuMAC_32[1,1] || vuMAC_32[2,1] || vuMAC_32[3,1];\nvuStatus_32[1,1] = vuMAC_32[4,1] || vuMAC_32[5,1] || vuMAC_32[6,1] || vuMAC_32[7,1];\nvuStatus_32[2,1] = vuMAC_32[8,1] || vuMAC_32[9,1] || vuMAC_32[10,1] || vuMAC_32[11,1];\nvuStatus_32[3,1] = vuMAC_32[12,1] || vuMAC_32[13,1] || vuMAC_32[14,1] || vuMAC_32[15,1];\nvuStatus_32[6,1] = vuStatus_32[6,1] || vuStatus_32[0,1];\nvuStatus_32[7,1] = vuStatus_32[7,1] || vuStatus_32[1,1];\nvuStatus_32[8,1] = vuStatus_32[8,1] || vuStatus_32[2,1];\nvuStatus_32[9,1] = vuStatus_32[9,1] || vuStatus_32[3,1];\n");
	}

	@Test
	public void opcodeVMADDBC() {
		assert runOpCode(PcodeInjectLibraryVu.VMADDBC).equals("VUFD[0,32] = vuACC[0,32] f+ VUFS[0,32] f* VUFT;\nvuMAC_32[3,1] = (VUFD[0,32] == 0);\nvuMAC_32[7,1] = (VUFD[0,32] < 0);\nvuMAC_32[11,1] = 0;\nvuMAC_32[15,1] = nan(VUFD[0,32]);\nVUFD[32,32] = vuACC[32,32] f+ VUFS[32,32] f* VUFT;\nvuMAC_32[2,1] = (VUFD[32,32] == 0);\nvuMAC_32[6,1] = (VUFD[32,32] < 0);\nvuMAC_32[10,1] = 0;\nvuMAC_32[14,1] = nan(VUFD[32,32]);\nvuMAC_32[1,1] = 0;\nvuMAC_32[5,1] = 0;\nvuMAC_32[9,1] = 0;\nvuMAC_32[13,1] = 0;\nVUFD[96,32] = vuACC[96,32] f+ VUFS[96,32] f* VUFT;\nvuMAC_32[0,1] = (VUFD[96,32] == 0);\nvuMAC_32[4,1] = (VUFD[96,32] < 0);\nvuMAC_32[8,1] = 0;\nvuMAC_32[12,1] = nan(VUFD[96,32]);\nvuStatus_32[0,1] = vuMAC_32[0,1] || vuMAC_32[1,1] || vuMAC_32[2,1] || vuMAC_32[3,1];\nvuStatus_32[1,1] = vuMAC_32[4,1] || vuMAC_32[5,1] || vuMAC_32[6,1] || vuMAC_32[7,1];\nvuStatus_32[2,1] = vuMAC_32[8,1] || vuMAC_32[9,1] || vuMAC_32[10,1] || vuMAC_32[11,1];\nvuStatus_32[3,1] = vuMAC_32[12,1] || vuMAC_32[13,1] || vuMAC_32[14,1] || vuMAC_32[15,1];\nvuStatus_32[6,1] = vuStatus_32[6,1] || vuStatus_32[0,1];\nvuStatus_32[7,1] = vuStatus_32[7,1] || vuStatus_32[1,1];\nvuStatus_32[8,1] = vuStatus_32[8,1] || vuStatus_32[2,1];\nvuStatus_32[9,1] = vuStatus_32[9,1] || vuStatus_32[3,1];\n");
	}

	@Test
	public void opcodeVSUB() {
		assert runOpCode(PcodeInjectLibraryVu.VSUB).equals("VUFD[0,32] = VUFS[0,32] f- VUFT[0,32];\nvuMAC_32[3,1] = (VUFD[0,32] == 0);\nvuMAC_32[7,1] = (VUFD[0,32] < 0);\nvuMAC_32[11,1] = nan(VUFD[0,32]);\nvuMAC_32[15,1] = 0;\nVUFD[32,32] = VUFS[32,32] f- VUFT[32,32];\nvuMAC_32[2,1] = (VUFD[32,32] == 0);\nvuMAC_32[6,1] = (VUFD[32,32] < 0);\nvuMAC_32[10,1] = nan(VUFD[32,32]);\nvuMAC_32[14,1] = 0;\nvuMAC_32[1,1] = 0;\nvuMAC_32[5,1] = 0;\nvuMAC_32[9,1] = 0;\nvuMAC_32[13,1] = 0;\nVUFD[96,32] = VUFS[96,32] f- VUFT[96,32];\nvuMAC_32[0,1] = (VUFD[96,32] == 0);\nvuMAC_32[4,1] = (VUFD[96,32] < 0);\nvuMAC_32[8,1] = nan(VUFD[96,32]);\nvuMAC_32[12,1] = 0;\nvuStatus_32[0,1] = vuMAC_32[0,1] || vuMAC_32[1,1] || vuMAC_32[2,1] || vuMAC_32[3,1];\nvuStatus_32[1,1] = vuMAC_32[4,1] || vuMAC_32[5,1] || vuMAC_32[6,1] || vuMAC_32[7,1];\nvuStatus_32[2,1] = vuMAC_32[8,1] || vuMAC_32[9,1] || vuMAC_32[10,1] || vuMAC_32[11,1];\nvuStatus_32[3,1] = vuMAC_32[12,1] || vuMAC_32[13,1] || vuMAC_32[14,1] || vuMAC_32[15,1];\nvuStatus_32[6,1] = vuStatus_32[6,1] || vuStatus_32[0,1];\nvuStatus_32[7,1] = vuStatus_32[7,1] || vuStatus_32[1,1];\nvuStatus_32[8,1] = vuStatus_32[8,1] || vuStatus_32[2,1];\nvuStatus_32[9,1] = vuStatus_32[9,1] || vuStatus_32[3,1];\n");
	}

	@Test
	public void opcodeVSUBBC() {
		assert runOpCode(PcodeInjectLibraryVu.VSUBBC).equals("VUFD[0,32] = VUFS[0,32] f- VUFT;\nvuMAC_32[3,1] = (VUFD[0,32] == 0);\nvuMAC_32[7,1] = (VUFD[0,32] < 0);\nvuMAC_32[11,1] = nan(VUFD[0,32]);\nvuMAC_32[15,1] = 0;\nVUFD[32,32] = VUFS[32,32] f- VUFT;\nvuMAC_32[2,1] = (VUFD[32,32] == 0);\nvuMAC_32[6,1] = (VUFD[32,32] < 0);\nvuMAC_32[10,1] = nan(VUFD[32,32]);\nvuMAC_32[14,1] = 0;\nvuMAC_32[1,1] = 0;\nvuMAC_32[5,1] = 0;\nvuMAC_32[9,1] = 0;\nvuMAC_32[13,1] = 0;\nVUFD[96,32] = VUFS[96,32] f- VUFT;\nvuMAC_32[0,1] = (VUFD[96,32] == 0);\nvuMAC_32[4,1] = (VUFD[96,32] < 0);\nvuMAC_32[8,1] = nan(VUFD[96,32]);\nvuMAC_32[12,1] = 0;\nvuStatus_32[0,1] = vuMAC_32[0,1] || vuMAC_32[1,1] || vuMAC_32[2,1] || vuMAC_32[3,1];\nvuStatus_32[1,1] = vuMAC_32[4,1] || vuMAC_32[5,1] || vuMAC_32[6,1] || vuMAC_32[7,1];\nvuStatus_32[2,1] = vuMAC_32[8,1] || vuMAC_32[9,1] || vuMAC_32[10,1] || vuMAC_32[11,1];\nvuStatus_32[3,1] = vuMAC_32[12,1] || vuMAC_32[13,1] || vuMAC_32[14,1] || vuMAC_32[15,1];\nvuStatus_32[6,1] = vuStatus_32[6,1] || vuStatus_32[0,1];\nvuStatus_32[7,1] = vuStatus_32[7,1] || vuStatus_32[1,1];\nvuStatus_32[8,1] = vuStatus_32[8,1] || vuStatus_32[2,1];\nvuStatus_32[9,1] = vuStatus_32[9,1] || vuStatus_32[3,1];\n");
	}

	@Test
	public void opcodeVMSUB() {
		assert runOpCode(PcodeInjectLibraryVu.VMSUB).equals("VUFD[0,32] = vuACC[0,32] f- VUFS[0,32] f* VUFT[0,32];\nvuMAC_32[3,1] = (VUFD[0,32] == 0);\nvuMAC_32[7,1] = (VUFD[0,32] < 0);\nvuMAC_32[11,1] = nan(VUFD[0,32]);\nvuMAC_32[15,1] = 0;\nVUFD[32,32] = vuACC[32,32] f- VUFS[32,32] f* VUFT[32,32];\nvuMAC_32[2,1] = (VUFD[32,32] == 0);\nvuMAC_32[6,1] = (VUFD[32,32] < 0);\nvuMAC_32[10,1] = nan(VUFD[32,32]);\nvuMAC_32[14,1] = 0;\nvuMAC_32[1,1] = 0;\nvuMAC_32[5,1] = 0;\nvuMAC_32[9,1] = 0;\nvuMAC_32[13,1] = 0;\nVUFD[96,32] = vuACC[96,32] f- VUFS[96,32] f* VUFT[96,32];\nvuMAC_32[0,1] = (VUFD[96,32] == 0);\nvuMAC_32[4,1] = (VUFD[96,32] < 0);\nvuMAC_32[8,1] = nan(VUFD[96,32]);\nvuMAC_32[12,1] = 0;\nvuStatus_32[0,1] = vuMAC_32[0,1] || vuMAC_32[1,1] || vuMAC_32[2,1] || vuMAC_32[3,1];\nvuStatus_32[1,1] = vuMAC_32[4,1] || vuMAC_32[5,1] || vuMAC_32[6,1] || vuMAC_32[7,1];\nvuStatus_32[2,1] = vuMAC_32[8,1] || vuMAC_32[9,1] || vuMAC_32[10,1] || vuMAC_32[11,1];\nvuStatus_32[3,1] = vuMAC_32[12,1] || vuMAC_32[13,1] || vuMAC_32[14,1] || vuMAC_32[15,1];\nvuStatus_32[6,1] = vuStatus_32[6,1] || vuStatus_32[0,1];\nvuStatus_32[7,1] = vuStatus_32[7,1] || vuStatus_32[1,1];\nvuStatus_32[8,1] = vuStatus_32[8,1] || vuStatus_32[2,1];\nvuStatus_32[9,1] = vuStatus_32[9,1] || vuStatus_32[3,1];\n");
	}

	@Test
	public void opcodeVMSUBBC() {
		assert runOpCode(PcodeInjectLibraryVu.VMSUBBC).equals("VUFD[0,32] = vuACC[0,32] f- VUFS[0,32] f* VUFT;\nvuMAC_32[3,1] = (VUFD[0,32] == 0);\nvuMAC_32[7,1] = (VUFD[0,32] < 0);\nvuMAC_32[11,1] = nan(VUFD[0,32]);\nvuMAC_32[15,1] = 0;\nVUFD[32,32] = vuACC[32,32] f- VUFS[32,32] f* VUFT;\nvuMAC_32[2,1] = (VUFD[32,32] == 0);\nvuMAC_32[6,1] = (VUFD[32,32] < 0);\nvuMAC_32[10,1] = nan(VUFD[32,32]);\nvuMAC_32[14,1] = 0;\nvuMAC_32[1,1] = 0;\nvuMAC_32[5,1] = 0;\nvuMAC_32[9,1] = 0;\nvuMAC_32[13,1] = 0;\nVUFD[96,32] = vuACC[96,32] f- VUFS[96,32] f* VUFT;\nvuMAC_32[0,1] = (VUFD[96,32] == 0);\nvuMAC_32[4,1] = (VUFD[96,32] < 0);\nvuMAC_32[8,1] = nan(VUFD[96,32]);\nvuMAC_32[12,1] = 0;\nvuStatus_32[0,1] = vuMAC_32[0,1] || vuMAC_32[1,1] || vuMAC_32[2,1] || vuMAC_32[3,1];\nvuStatus_32[1,1] = vuMAC_32[4,1] || vuMAC_32[5,1] || vuMAC_32[6,1] || vuMAC_32[7,1];\nvuStatus_32[2,1] = vuMAC_32[8,1] || vuMAC_32[9,1] || vuMAC_32[10,1] || vuMAC_32[11,1];\nvuStatus_32[3,1] = vuMAC_32[12,1] || vuMAC_32[13,1] || vuMAC_32[14,1] || vuMAC_32[15,1];\nvuStatus_32[6,1] = vuStatus_32[6,1] || vuStatus_32[0,1];\nvuStatus_32[7,1] = vuStatus_32[7,1] || vuStatus_32[1,1];\nvuStatus_32[8,1] = vuStatus_32[8,1] || vuStatus_32[2,1];\nvuStatus_32[9,1] = vuStatus_32[9,1] || vuStatus_32[3,1];\n");
	}

	@Test
	public void opcodeVMUL() {
		assert runOpCode(PcodeInjectLibraryVu.VMUL).equals("VUFD[0,32] = VUFS[0,32] f* VUFT[0,32];\nvuMAC_32[3,1] = (VUFD[0,32] == 0);\nvuMAC_32[7,1] = (VUFD[0,32] < 0);\nvuMAC_32[11,1] = 0;\nvuMAC_32[15,1] = 0;\nVUFD[32,32] = VUFS[32,32] f* VUFT[32,32];\nvuMAC_32[2,1] = (VUFD[32,32] == 0);\nvuMAC_32[6,1] = (VUFD[32,32] < 0);\nvuMAC_32[10,1] = 0;\nvuMAC_32[14,1] = 0;\nvuMAC_32[1,1] = 0;\nvuMAC_32[5,1] = 0;\nvuMAC_32[9,1] = 0;\nvuMAC_32[13,1] = 0;\nVUFD[96,32] = VUFS[96,32] f* VUFT[96,32];\nvuMAC_32[0,1] = (VUFD[96,32] == 0);\nvuMAC_32[4,1] = (VUFD[96,32] < 0);\nvuMAC_32[8,1] = 0;\nvuMAC_32[12,1] = 0;\nvuStatus_32[0,1] = vuMAC_32[0,1] || vuMAC_32[1,1] || vuMAC_32[2,1] || vuMAC_32[3,1];\nvuStatus_32[1,1] = vuMAC_32[4,1] || vuMAC_32[5,1] || vuMAC_32[6,1] || vuMAC_32[7,1];\nvuStatus_32[2,1] = vuMAC_32[8,1] || vuMAC_32[9,1] || vuMAC_32[10,1] || vuMAC_32[11,1];\nvuStatus_32[3,1] = vuMAC_32[12,1] || vuMAC_32[13,1] || vuMAC_32[14,1] || vuMAC_32[15,1];\nvuStatus_32[6,1] = vuStatus_32[6,1] || vuStatus_32[0,1];\nvuStatus_32[7,1] = vuStatus_32[7,1] || vuStatus_32[1,1];\nvuStatus_32[8,1] = vuStatus_32[8,1] || vuStatus_32[2,1];\nvuStatus_32[9,1] = vuStatus_32[9,1] || vuStatus_32[3,1];\n");
	}

	@Test
	public void opcodeVMULBC() {
		assert runOpCode(PcodeInjectLibraryVu.VMULBC).equals("VUFD[0,32] = VUFS[0,32] f* VUFT;\nvuMAC_32[3,1] = (VUFD[0,32] == 0);\nvuMAC_32[7,1] = (VUFD[0,32] < 0);\nvuMAC_32[11,1] = 0;\nvuMAC_32[15,1] = 0;\nVUFD[32,32] = VUFS[32,32] f* VUFT;\nvuMAC_32[2,1] = (VUFD[32,32] == 0);\nvuMAC_32[6,1] = (VUFD[32,32] < 0);\nvuMAC_32[10,1] = 0;\nvuMAC_32[14,1] = 0;\nvuMAC_32[1,1] = 0;\nvuMAC_32[5,1] = 0;\nvuMAC_32[9,1] = 0;\nvuMAC_32[13,1] = 0;\nVUFD[96,32] = VUFS[96,32] f* VUFT;\nvuMAC_32[0,1] = (VUFD[96,32] == 0);\nvuMAC_32[4,1] = (VUFD[96,32] < 0);\nvuMAC_32[8,1] = 0;\nvuMAC_32[12,1] = 0;\nvuStatus_32[0,1] = vuMAC_32[0,1] || vuMAC_32[1,1] || vuMAC_32[2,1] || vuMAC_32[3,1];\nvuStatus_32[1,1] = vuMAC_32[4,1] || vuMAC_32[5,1] || vuMAC_32[6,1] || vuMAC_32[7,1];\nvuStatus_32[2,1] = vuMAC_32[8,1] || vuMAC_32[9,1] || vuMAC_32[10,1] || vuMAC_32[11,1];\nvuStatus_32[3,1] = vuMAC_32[12,1] || vuMAC_32[13,1] || vuMAC_32[14,1] || vuMAC_32[15,1];\nvuStatus_32[6,1] = vuStatus_32[6,1] || vuStatus_32[0,1];\nvuStatus_32[7,1] = vuStatus_32[7,1] || vuStatus_32[1,1];\nvuStatus_32[8,1] = vuStatus_32[8,1] || vuStatus_32[2,1];\nvuStatus_32[9,1] = vuStatus_32[9,1] || vuStatus_32[3,1];\n");
	}

	@Test
	public void opcodeVFTOI() {
		assert runOpCode(PcodeInjectLibraryVu.VFTOI).equals("VUFT[0,32] = trunc(VUFS[0,32]);\nVUFT[32,32] = trunc(VUFS[32,32]);\nVUFT[96,32] = trunc(VUFS[96,32]);\n");
	}

	@Test
	public void opcodeVITOF() {
		assert runOpCode(PcodeInjectLibraryVu.VITOF).equals("VUFT[0,32] = int2float(VUFS[0,32]);\nVUFT[32,32] = int2float(VUFS[32,32]);\nVUFT[96,32] = int2float(VUFS[96,32]);\n");
	}

	@Test
	public void opcodeVULQ() {
		assert runOpCode(PcodeInjectLibraryVu.VULQ).equals("VUFT[0,32] = *:4 (addr + 12);\nVUFT[32,32] = *:4 (addr + 8);\nVUFT[96,32] = *:4 (addr + 0);\n");
	}

	@Test
	public void opcodeVUSQ() {
		assert runOpCode(PcodeInjectLibraryVu.VUSQ).equals("*:4 (addr + 12) = VUFS[0,32];\n*:4 (addr + 8) = VUFS[32,32];\n*:4 (addr + 0) = VUFS[96,32];\n");
	}

	@Test
	public void opcodeVMAX() {
		assert runOpCode(PcodeInjectLibraryVu.VMAX).equals("if (VUFS[0,32] f> VUFT[0,32]) goto <max3>;\nVUFD[0,32] = VUFT[0,32];\ngoto <end3>;\n<max3>\nVUFD[0,32] = VUFS[0,32];\n<end3>\nif (VUFS[32,32] f> VUFT[32,32]) goto <max2>;\nVUFD[32,32] = VUFT[32,32];\ngoto <end2>;\n<max2>\nVUFD[32,32] = VUFS[32,32];\n<end2>\nif (VUFS[96,32] f> VUFT[96,32]) goto <max0>;\nVUFD[96,32] = VUFT[96,32];\ngoto <end0>;\n<max0>\nVUFD[96,32] = VUFS[96,32];\n<end0>\n");
	}

	@Test
	public void opcodeVMAXBC() {
		assert runOpCode(PcodeInjectLibraryVu.VMAXBC).equals("if (VUFS[0,32] f> VUFT) goto <max3>;\nVUFD[0,32] = VUFT;\ngoto <end3>;\n<max3>\nVUFD[0,32] = VUFS[0,32];\n<end3>\nif (VUFS[32,32] f> VUFT) goto <max2>;\nVUFD[32,32] = VUFT;\ngoto <end2>;\n<max2>\nVUFD[32,32] = VUFS[32,32];\n<end2>\nif (VUFS[96,32] f> VUFT) goto <max0>;\nVUFD[96,32] = VUFT;\ngoto <end0>;\n<max0>\nVUFD[96,32] = VUFS[96,32];\n<end0>\n");
	}

	@Test
	public void opcodeVMIN() {
		assert runOpCode(PcodeInjectLibraryVu.VMIN).equals("if (VUFS[0,32] f< VUFT[0,32]) goto <min3>;\nVUFD[0,32] = VUFT[0,32];\ngoto <end3>;\n<min3>\nVUFD[0,32] = VUFS[0,32];\n<end3>\nif (VUFS[32,32] f< VUFT[32,32]) goto <min2>;\nVUFD[32,32] = VUFT[32,32];\ngoto <end2>;\n<min2>\nVUFD[32,32] = VUFS[32,32];\n<end2>\nif (VUFS[96,32] f< VUFT[96,32]) goto <min0>;\nVUFD[96,32] = VUFT[96,32];\ngoto <end0>;\n<min0>\nVUFD[96,32] = VUFS[96,32];\n<end0>\n");
	}

	@Test
	public void opcodeVMINBC() {
		assert runOpCode(PcodeInjectLibraryVu.VMINBC).equals("if (VUFS[0,32] f< VUFT) goto <min3>;\nVUFD[0,32] = VUFT;\ngoto <end3>;\n<min3>\nVUFD[0,32] = VUFS[0,32];\n<end3>\nif (VUFS[32,32] f< VUFT) goto <min2>;\nVUFD[32,32] = VUFT;\ngoto <end2>;\n<min2>\nVUFD[32,32] = VUFS[32,32];\n<end2>\nif (VUFS[96,32] f< VUFT) goto <min0>;\nVUFD[96,32] = VUFT;\ngoto <end0>;\n<min0>\nVUFD[96,32] = VUFS[96,32];\n<end0>\n");
	}

	@Test
	public void opcodeVMFIR() {
		assert runOpCode(PcodeInjectLibraryVu.VMFIR).equals("VUFT[0,32] = sext(VUIS);\nVUFT[32,32] = sext(VUIS);\nVUFT[96,32] = sext(VUIS);\n");
	}

	@Test
	public void opcodeVMOVE() {
		assert runOpCode(PcodeInjectLibraryVu.VMOVE).equals("VUFT[0,32] = VUFS[0,32];\nVUFT[32,32] = VUFS[32,32];\nVUFT[96,32] = VUFS[96,32];\n");
	}

	@Test
	public void opcodeVMOVEBC() {
		assert runOpCode(PcodeInjectLibraryVu.VMOVEBC).equals("VUFT[0,32] = VUFS;\nVUFT[32,32] = VUFS;\nVUFT[96,32] = VUFS;\n");
	}

	@Test
	public void opcodeVMR32() {
		assert runOpCode(PcodeInjectLibraryVu.VMR32).equals("VUFT[0,32] = VUFS[32,32];\nVUFT[32,32] = VUFS[64,32];\nVUFT[96,32] = VUFS[0,32];\n");
	}

	@Test
	public void opcodeVCLEAR() {
		assert runOpCode(PcodeInjectLibraryVu.VCLEAR).equals("VUFD[0,32] = int2float(0:4);\nVUFD[32,32] = int2float(0:4);\nVUFD[96,32] = int2float(0:4);\n");
	}

}
