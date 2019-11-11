/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

 // InjectPayloadJava modified for use with ghidra-emotionengine

package ghidra.emotionengine;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.template.ConstructTpl;
import ghidra.app.plugin.processors.sleigh.template.OpTpl;
import ghidra.pcodeCPort.slgh_compile.PcodeParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeXMLException;
import ghidra.sleigh.grammar.Location;
import ghidra.util.Msg;
import ghidra.util.xml.XmlUtilities;
import ghidra.xml.XmlPullParser;
import ghidra.xml.XmlPullParserFactory;

public class InjectPayloadVu extends InjectPayloadCallother {
    private SleighLanguage language;
    private SAXParser saxParser;

	private static final String FLOAT_ADD = " f+ ";
	private static final String INT_ADD = " + ";
	private static final String FLOAT_SUB = " f- ";
	private static final String FLOAT_MUL = " f* ";
	private static final String FLOAT_GREATER_THAN = " f> ";
	private static final String FLOAT_LESS_THAN = " f< ";
	private static final String ASSIGNMENT = " = ";
	private static final String GOTO = " goto ";
	private static final String IF = "if (";
	private static final String MAX = "<max";
	private static final String MIN = "<min";
	private static final String END = "<end";
	private static final String SEXT = "sext(";
    private static final String ABS = "abs";
	private static final String INT2FLOAT = "int2float";
	private static final String FLOAT_NAN = "nan";
    private static final String TRUNC = "trunc";
	private static final String END_LINE = ";\n";
	private static final String LOGICAL_OR = " || ";

    private static final String VUFD = "VUFD";
    private static final String VUFS = "VUFS";
	private static final String VUFT = "VUFT";
	private static final String VUIS = "VUIS";
	private static final String VUACC = "vuACC";

	private static final String ADDRESS = "addr";
	private static final String FLOAT_POINTER = "*:4 ";
	private static final String BROADCAST = "BC";
	private static final String VEC_ZERO = "vf0";

	private static final String SUB = "SUB";
	private static final String ADD = "ADD";

	private static final String[] ZERO = new String[]{
		"int2float(1:4)",
		"int2float(0:4)",
		"int2float(0:4)",
		"int2float(0:4)"
	};
    private static final String[] VECTOR_DIRECTIONS = new String[]{
        "[96,32]",
        "[64,32]",
        "[32,32]",
        "[0,32]"
	};

	private static final String[][] MAC = new String[][]{
		new String[]{"vuMAC_32[0,1]", "vuMAC_32[1,1]", "vuMAC_32[2,1]", "vuMAC_32[3,1]"},
		new String[]{"vuMAC_32[4,1]", "vuMAC_32[5,1]", "vuMAC_32[6,1]", "vuMAC_32[7,1]"},
		new String[]{"vuMAC_32[8,1]", "vuMAC_32[9,1]", "vuMAC_32[10,1]", "vuMAC_32[11,1]"},
		new String[]{"vuMAC_32[12,1]", "vuMAC_32[13,1]", "vuMAC_32[14,1]", "vuMAC_32[15,1]"}
	};

	private static final String[] STATUS = new String[]{
		"vuStatus_32[0,1]",
		"vuStatus_32[1,1]",
		"vuStatus_32[2,1]",
		"vuStatus_32[3,1]",
		"vuStatus_32[4,1]",
		"vuStatus_32[5,1]",
		"vuStatus_32[6,1]",
		"vuStatus_32[7,1]",
		"vuStatus_32[8,1]",
		"vuStatus_32[9,1]",
		"vuStatus_32[10,1]",
		"vuStatus_32[11,1]"
	};

	private static final String OPEN_COND = " (";
	private static final String ZERO_COND = " == 0 ";
	private static final String LT_ZERO_COND = " < 0 ";
	private static final String CLOSE_COND = ");\n";

	private long dest;
	
	private static final Map<String, Function<InjectPayloadVu, String>>
		INSTRUCTIONS = getInstructionMap();
	private static final Map<String, String> OPERATIONS = getOperationMap();

    public InjectPayloadVu(String sourceName, SleighLanguage language) {
		super(sourceName);
		this.language = language;
		try {
			saxParser = getSAXParser();
		}
		catch (PcodeXMLException e) {
			Msg.error(this, e);
		}
	}

	SleighLanguage getLanguage() {
		return language;
	}

	InjectContext getInjectContext(Program program, String context) {
		InjectContext injectContext = new InjectContext();
		injectContext.language = language;
		try {
			injectContext.restoreXml(saxParser, context, program.getAddressFactory());
			saxParser.reset();
		}
		catch (PcodeXMLException e) {
			Msg.error(this, e);
		}
		return injectContext;
	}

	private static SAXParser getSAXParser() throws PcodeXMLException {
		try {
			SAXParserFactory saxParserFactory = XmlUtilities.createSecureSAXParserFactory(false);
			saxParserFactory.setFeature("http://xml.org/sax/features/namespaces", false);
			saxParserFactory.setFeature("http://xml.org/sax/features/validation", false);
			return saxParserFactory.newSAXParser();
		}
		catch (Exception e) {
			throw new PcodeXMLException("Failed to instantiate XML parser", e);
		}
	}

	public OpTpl[] getPcode(PcodeParser parser, Program program, String context) {
		Address vf0Address = program.getRegister(VEC_ZERO).getAddress();
		if (!INSTRUCTIONS.containsKey(getName())) {
			return new OpTpl[0];
		}
		String sourceName = getSource();
		Location loc = new Location(sourceName, 1);
		InjectParameter[] input = getInput();
		for (InjectParameter element : input) {
			parser.addOperand(loc, element.getName(), element.getIndex());
		}
		InjectParameter[] output = getOutput();
		for (InjectParameter element : output) {
			parser.addOperand(loc, element.getName(), element.getIndex());
		}
		InjectContext injectContext = getInjectContext(program, context);
		dest = injectContext.inputlist.get(0).getOffset();
		Function<InjectPayloadVu, String> function = INSTRUCTIONS.get(name);
		StringBuilder pcodeTextBuilder = new StringBuilder();
		for (int i = 1; i < injectContext.inputlist.size(); i++) {
			if (injectContext.inputlist.get(i).getSize() == 0x10) {
				if (vf0Address.equals(injectContext.inputlist.get(i).getAddress())) {
					pcodeTextBuilder.append(setZero(dest, input[i].getName()));
				}
			}
		}
		pcodeTextBuilder.append(function.apply(this));
		String constructTplXml =
			PcodeParser.stringifyTemplate(parser.compilePcode(
				pcodeTextBuilder.toString(), sourceName, 1));
		if (constructTplXml == null) {
			throw new SleighException("pcode compile failed " + sourceName);
		}
		final SAXParseException[] exception = new SAXParseException[1];
		XmlPullParser xmlParser = null;
		try {
			xmlParser =
				XmlPullParserFactory.create(constructTplXml, sourceName, new ErrorHandler() {
					@Override
					public void warning(SAXParseException e) throws SAXException {
						Msg.warn(this, e.getMessage());
					}

					@Override
					public void fatalError(SAXParseException e) throws SAXException {
						exception[0] = e;
					}

					@Override
					public void error(SAXParseException e) throws SAXException {
						exception[0] = e;
					}
				}, false);
		}
		catch (SAXException e) {
			Msg.error(this, e);
		}

		ConstructTpl constructTpl = new ConstructTpl();
		try {
			constructTpl.restoreXml(xmlParser, language.getAddressFactory());
		}
		catch (UnknownInstructionException e) {
			Msg.error(this, e);
		}
		if (exception[0] != null) {
			throw new SleighException("pcode compiler returned invalid xml " + sourceName,
				exception[0]);
		}
		OpTpl[] opTemplates = constructTpl.getOpVec();
		setTemplate(constructTpl);
		return opTemplates;
	}
	
	private String setZero(long dest, String register) {
		final int MAX_STRING_LENGTH = 119;
		StringBuilder builder = new StringBuilder(MAX_STRING_LENGTH);
		for(int i = 3; i >= 0; i--) {
			if (((dest >> i) & 1) == 1) {
				builder.append(register)
				.append(VECTOR_DIRECTIONS[i])
				.append(ASSIGNMENT)
				.append(ZERO[i])
				.append(END_LINE);
			}
		}
		return builder.toString();
	}

	private static final String buildMac(int index, String name) {
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < 4; i++) {
			builder.append(MAC[i][index])
				   .append(ASSIGNMENT);
			switch(i) {
				case 0:
					// result == 0
					builder.append(OPEN_COND)
						   .append(VUFD)
						   .append(VECTOR_DIRECTIONS[index])
						   .append(ZERO_COND)
						   .append(CLOSE_COND);
					break;
				case 1:
					// result < 0
					builder.append(OPEN_COND)
						   .append(VUFD)
						   .append(VECTOR_DIRECTIONS[index])
						   .append(LT_ZERO_COND)
						   .append(CLOSE_COND);
					break;
				case 2:
					// underflow
					if (name.contains(SUB)) {
						builder.append(FLOAT_NAN)
							   .append('(')
							   .append(VUFD)
							   .append(VECTOR_DIRECTIONS[index])
							   .append(')')
							   .append(END_LINE);
					} else {
						builder.append('0')
							   .append(END_LINE);
					}
					break;
				case 3:
					// overflow
					if (name.contains(ADD)) {
						builder.append(FLOAT_NAN)
							   .append('(')
							   .append(VUFD)
							   .append(VECTOR_DIRECTIONS[index])
							   .append(')')
							   .append(END_LINE);
					} else {
						builder.append('0')
							   .append(END_LINE);
					}
					break;
				default:
					break;
			}
		}
		return builder.toString();
	}

	private static String clearMac(int index) {
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < 4; i++) {
			builder.append(MAC[i][index])
				   .append(ASSIGNMENT)
				   .append('0')
				   .append(END_LINE);
		}
		return builder.toString();
	}

	private static String buildStatus() {
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < 4; i++) {
			builder.append(STATUS[i])
				   .append(ASSIGNMENT)
				   .append(MAC[i][0])
				   .append(LOGICAL_OR)
				   .append(MAC[i][1])
				   .append(LOGICAL_OR)
				   .append(MAC[i][2])
				   .append(LOGICAL_OR)
				   .append(MAC[i][3])
				   .append(END_LINE);
		}
		for (int i = 6; i <= 9; i++) {
			builder.append(STATUS[i])
				   .append(ASSIGNMENT)
				   .append(STATUS[i])
				   .append(LOGICAL_OR)
				   .append(STATUS[i-6])
				   .append(END_LINE);
		}
		return builder.toString();
	}

    private static String getOperationText1(InjectPayloadVu self) {
		StringBuilder builder = new StringBuilder();
		String operation = OPERATIONS.get(self.name);
		for(int i = 3; i >= 0; i--) {
			if (((self.dest >> i) & 1) == 1) {
				builder.append(VUFT)
				.append(VECTOR_DIRECTIONS[i])
				.append(ASSIGNMENT)
				.append(operation)
				.append('(')
				.append(VUFS)
				.append(VECTOR_DIRECTIONS[i])
				.append(')')
				.append(END_LINE);
			}
		}
		return builder.toString();
	}

    private static String getOperationText3(InjectPayloadVu self) {
		StringBuilder builder = new StringBuilder();
		boolean broadcast = self.name.endsWith(BROADCAST);
		String operation = OPERATIONS.get(self.name);
		for(int i = 3; i >= 0; i--) {
			if (((self.dest >> i) & 1) == 1) {
				builder.append(VUFD)
				.append(VECTOR_DIRECTIONS[i])
				.append(ASSIGNMENT)
				.append(VUFS)
				.append(VECTOR_DIRECTIONS[i])
				.append(operation)
				.append(VUFT);
				if (!broadcast) {
					builder.append(VECTOR_DIRECTIONS[i]);
				}
				builder.append(END_LINE)
					   .append(buildMac(i, self.name));
			} else {
				builder.append(clearMac(i));
			}
		}
		return builder.append(buildStatus()).toString();
	}
	
	private static String getMultiplyOperationText3(InjectPayloadVu self) {
		StringBuilder builder = new StringBuilder();
		boolean broadcast = self.name.endsWith(BROADCAST);
		String operation = OPERATIONS.get(self.name);
		for(int i = 3; i >= 0; i--) {
			if (((self.dest >> i) & 1) == 1) {
				builder.append(VUFD)
				.append(VECTOR_DIRECTIONS[i])
				.append(ASSIGNMENT)
				.append(VUACC)
				.append(VECTOR_DIRECTIONS[i])
				.append(operation)
				.append(VUFS)
				.append(VECTOR_DIRECTIONS[i])
				.append(FLOAT_MUL)
				.append(VUFT);
				if (!broadcast) {
					builder.append(VECTOR_DIRECTIONS[i]);
				}
				builder.append(END_LINE)
					   .append(buildMac(i, self.name));
			} else {
				builder.append(clearMac(i));
			}
		}
		return builder.append(buildStatus()).toString();
	}
	
	private static String getLoadText(InjectPayloadVu self) {
            StringBuilder builder = new StringBuilder();
            for(int i = 3; i >= 0; i--) {
                if (((self.dest >> i) & 1) == 1) {
                    builder.append(VUFT)
                    .append(VECTOR_DIRECTIONS[i])
                    .append(ASSIGNMENT)
					.append(FLOAT_POINTER)
					.append('(')
					.append(ADDRESS)
					.append(INT_ADD)
					.append(Integer.toString(4*i))
					.append(')')
					.append(END_LINE);
                }
            }
            return builder.toString();
	}
	
	private static String getStoreText(InjectPayloadVu self) {
		StringBuilder builder = new StringBuilder();
		for(int i = 3; i >= 0; i--) {
			if (((self.dest >> i) & 1) == 1) {
				builder.append(FLOAT_POINTER)
					   .append('(')
					   .append(ADDRESS)
					   .append(INT_ADD)
					   .append(Integer.toString(4*i))
					   .append(')')
					   .append(ASSIGNMENT)
					   .append(VUFS)
					   .append(VECTOR_DIRECTIONS[i])
					   .append(END_LINE);
			}
		}
		return builder.toString();
	}

	private static String getMaxText(InjectPayloadVu self) {
		boolean broadcast = self.name.endsWith(BROADCAST);
		StringBuilder builder = new StringBuilder();
		for(int i = 3; i >= 0; i--) {
			if (((self.dest >> i) & 1) == 1) {
				String max = new StringBuilder(MAX)
							.append(Integer.toString(i))
							.append('>').toString();
				String end = new StringBuilder(END)
							.append(Integer.toString(i))
							.append('>').toString();
				builder.append(IF)
				.append(VUFS)
				.append(VECTOR_DIRECTIONS[i])
				.append(FLOAT_GREATER_THAN)
				.append(VUFT);
				if (!broadcast) {
					builder.append(VECTOR_DIRECTIONS[i]);
				}
				builder.append(')')
				.append(' ')
				.append(GOTO)
				.append(max)
				.append(END_LINE)
				.append(VUFD)
				.append(VECTOR_DIRECTIONS[i])
				.append(ASSIGNMENT)
				.append(VUFT);
				if (!broadcast) {
					builder.append(VECTOR_DIRECTIONS[i]);
				}
				builder.append(END_LINE)
				.append(GOTO)
				.append(end)
				.append(END_LINE)
				.append(max)
				.append('\n')
				.append(VUFD)
				.append(VECTOR_DIRECTIONS[i])
				.append(ASSIGNMENT)
				.append(VUFS)
				.append(VECTOR_DIRECTIONS[i])
				.append(END_LINE)
				.append(end);
			}
		}
		return builder.toString();
	}

	private static String getMinText(InjectPayloadVu self) {
		boolean broadcast = self.name.endsWith(BROADCAST);
		StringBuilder builder = new StringBuilder();
		for(int i = 3; i >= 0; i--) {
			if (((self.dest >> i) & 1) == 1) {
				String max = new StringBuilder(MIN)
							.append(Integer.toString(i))
							.append('>').toString();
				String end = new StringBuilder(END)
							.append(Integer.toString(i))
							.append('>').toString();
				builder.append(IF)
				.append(VUFS)
				.append(VECTOR_DIRECTIONS[i])
				.append(FLOAT_LESS_THAN)
				.append(VUFT);
				if (!broadcast) {
					builder.append(VECTOR_DIRECTIONS[i]);
				}
				builder.append(')')
				.append(' ')
				.append(GOTO)
				.append(max)
				.append(END_LINE)
				.append(VUFD)
				.append(VECTOR_DIRECTIONS[i])
				.append(ASSIGNMENT)
				.append(VUFT);
				if (!broadcast) {
					builder.append(VECTOR_DIRECTIONS[i]);
				}
				builder.append(END_LINE)
				.append(GOTO)
				.append(end)
				.append(END_LINE)
				.append(max)
				.append('\n')
				.append(VUFD)
				.append(VECTOR_DIRECTIONS[i])
				.append(ASSIGNMENT)
				.append(VUFS)
				.append(VECTOR_DIRECTIONS[i])
				.append(END_LINE)
				.append(end);
			}
		}
		return builder.toString();
	}

	private static String getMFIRText(InjectPayloadVu self) {
		StringBuilder builder = new StringBuilder();
		for(int i = 3; i >= 0; i--) {
			if (((self.dest >> i) & 1) == 1) {
				builder.append(VUFT)
				.append(VECTOR_DIRECTIONS[i])
				.append(ASSIGNMENT)
				.append(SEXT)
				.append(VUIS)
				.append(')')
				.append(END_LINE);
			}
		}
		return builder.toString();
	}

	private static String getMoveText(InjectPayloadVu self) {
		StringBuilder builder = new StringBuilder();
		boolean broadcast = self.name.endsWith(BROADCAST);
		for(int i = 3; i >= 0; i--) {
			if (((self.dest >> i) & 1) == 1) {
				builder.append(VUFT)
				.append(VECTOR_DIRECTIONS[i])
				.append(ASSIGNMENT)
				.append(VUFS);
				if (!broadcast) {
					builder.append(VECTOR_DIRECTIONS[i]);
				}
				builder.append(END_LINE);
			}
		}
		return builder.toString();
	}

	private static String getMoveRotateText(InjectPayloadVu self) {
		StringBuilder builder = new StringBuilder();
		for(int i = 3; i >= 0; i--) {
			if (((self.dest >> i) & 1) == 1) {
				builder.append(VUFT)
				.append(VECTOR_DIRECTIONS[i])
				.append(ASSIGNMENT)
				.append(VUFS);
				if (i-1 < 0) {
					builder.append(VECTOR_DIRECTIONS[3]);
				} else {
					builder.append(VECTOR_DIRECTIONS[i-1]);
				}
				builder.append(END_LINE);
			}
		}
		return builder.toString();
	}

	private static String clearRegister(InjectPayloadVu self) {
		StringBuilder builder = new StringBuilder();
		for(int i = 3; i >= 0; i--) {
			if (((self.dest >> i) & 1) == 1) {
				builder.append(VUFD)
					   .append(VECTOR_DIRECTIONS[i])
					   .append(ASSIGNMENT)
					   .append(ZERO[1])
					   .append(END_LINE);
			}
		}
		return builder.toString();
	}

    private static Map<String, Function<InjectPayloadVu, String>> getInstructionMap() {
		Map<String, Function<InjectPayloadVu, String>> instructions = new HashMap<>();
		instructions.put(PcodeInjectLibraryVu.VABS, InjectPayloadVu::getOperationText1);
		instructions.put(PcodeInjectLibraryVu.VADD, InjectPayloadVu::getOperationText3);
		instructions.put(PcodeInjectLibraryVu.VADDBC, InjectPayloadVu::getOperationText3);
		instructions.put(PcodeInjectLibraryVu.VMADD, InjectPayloadVu::getMultiplyOperationText3);
		instructions.put(PcodeInjectLibraryVu.VMADDBC, InjectPayloadVu::getMultiplyOperationText3);
		instructions.put(PcodeInjectLibraryVu.VSUB, InjectPayloadVu::getOperationText3);
		instructions.put(PcodeInjectLibraryVu.VSUBBC, InjectPayloadVu::getOperationText3);
		instructions.put(PcodeInjectLibraryVu.VMUL, InjectPayloadVu::getOperationText3);
		instructions.put(PcodeInjectLibraryVu.VMULBC, InjectPayloadVu::getOperationText3);
		instructions.put(PcodeInjectLibraryVu.VMSUB, InjectPayloadVu::getMultiplyOperationText3);
		instructions.put(PcodeInjectLibraryVu.VMSUBBC, InjectPayloadVu::getMultiplyOperationText3);
		instructions.put(PcodeInjectLibraryVu.VFTOI, InjectPayloadVu::getOperationText1);
		instructions.put(PcodeInjectLibraryVu.VITOF, InjectPayloadVu::getOperationText1);
		instructions.put(PcodeInjectLibraryVu.VULQ, InjectPayloadVu::getLoadText);
		instructions.put(PcodeInjectLibraryVu.VUSQ, InjectPayloadVu::getStoreText);
		instructions.put(PcodeInjectLibraryVu.VMAX, InjectPayloadVu::getMaxText);
		instructions.put(PcodeInjectLibraryVu.VMAXBC, InjectPayloadVu::getMaxText);
		instructions.put(PcodeInjectLibraryVu.VMIN, InjectPayloadVu::getMinText);
		instructions.put(PcodeInjectLibraryVu.VMINBC, InjectPayloadVu::getMinText);
		instructions.put(PcodeInjectLibraryVu.VMFIR, InjectPayloadVu::getMFIRText);
		instructions.put(PcodeInjectLibraryVu.VMOVE, InjectPayloadVu::getMoveText);
		instructions.put(PcodeInjectLibraryVu.VMOVEBC, InjectPayloadVu::getMoveText);
		instructions.put(PcodeInjectLibraryVu.VMR32, InjectPayloadVu::getMoveRotateText);
		instructions.put(PcodeInjectLibraryVu.VCLEAR, InjectPayloadVu::clearRegister);
		return Collections.unmodifiableMap(instructions);
	}
	
	private static Map<String, String> getOperationMap() {
		Map<String, String> operations = new HashMap<>();
		operations.put(PcodeInjectLibraryVu.VABS, ABS);
		operations.put(PcodeInjectLibraryVu.VADD, FLOAT_ADD);
		operations.put(PcodeInjectLibraryVu.VADDBC,FLOAT_ADD);
		operations.put(PcodeInjectLibraryVu.VMADD, FLOAT_ADD);
		operations.put(PcodeInjectLibraryVu.VMADDBC, FLOAT_ADD);
		operations.put(PcodeInjectLibraryVu.VSUB, FLOAT_SUB);
		operations.put(PcodeInjectLibraryVu.VSUBBC, FLOAT_SUB);
		operations.put(PcodeInjectLibraryVu.VMUL, FLOAT_MUL);
		operations.put(PcodeInjectLibraryVu.VMULBC, FLOAT_MUL);
		operations.put(PcodeInjectLibraryVu.VMSUB, FLOAT_SUB);
		operations.put(PcodeInjectLibraryVu.VMSUBBC, FLOAT_SUB);
		operations.put(PcodeInjectLibraryVu.VFTOI, TRUNC);
		operations.put(PcodeInjectLibraryVu.VITOF, INT2FLOAT);
		return Collections.unmodifiableMap(operations);
	}
}
