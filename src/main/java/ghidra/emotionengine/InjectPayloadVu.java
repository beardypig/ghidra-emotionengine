/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	  http://www.apache.org/licenses/LICENSE-2.0
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

import org.jdom.JDOMException;
import org.xml.sax.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import ghidra.app.plugin.processors.sleigh.ParserWalker;
import ghidra.app.plugin.processors.sleigh.PcodeEmitObjects;
import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.SleighParserContext;
import ghidra.app.plugin.processors.sleigh.template.ConstructTpl;
import ghidra.pcodeCPort.slgh_compile.PcodeParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeXMLException;
import ghidra.sleigh.grammar.Location;
import ghidra.util.Msg;
import ghidra.util.xml.XmlUtilities;
import ghidra.xml.XmlPullParser;
import ghidra.xml.XmlPullParserFactory;

public class InjectPayloadVu extends InjectPayloadCallother {

	private static final String FLOAT_ADD = "f+";
	private static final String FLOAT_SUB = "f-";
	private static final String FLOAT_MUL = "f*";
	private static final String ABS = "abs";
	private static final String INT2FLOAT = "int2float";
	private static final String TRUNC = "trunc";

	private static final String VUFD = "VUFD";
	private static final String BROADCAST = "BC";
	private static final String VEC_ZERO = "vf0";

	private static final String[] VECTOR_DIRECTIONS = new String[]{
		"[96,32]",
		"[64,32]",
		"[32,32]",
		"[0,32]"
	};

	private static final String NAN_COND = "vuMAC_32[%d,1] = nan(VUFD%s);\n";
	private static final String CLEAR_MAC = "vuMAC_32[%d,1] = 0;\n";

	private static final String SET_ZERO = "%s%s = int2float(%d:4);\n";
	private static final String STATUS_LOWER =
		"vuStatus_32[%d,1] = vuMAC_32[%d,1] || vuMAC_32[%d,1]"
		+" || vuMAC_32[%d,1] || vuMAC_32[%d,1];\n";

	private static final String MAX_OPERATION = String.join("\n",
		"if (VUFS%1$s f> VUFT%2$s) goto <max%3$d>;",
		"VUFD%1$s = VUFT%2$s;",
		"goto <end%3$d>;",
		"<max%3$d>",
		"VUFD%1$s = VUFS%1$s;",
		"<end%3$d>\n");
	private static final String MIN_OPERATION = String.join("\n",
		"if (VUFS%1$s f< VUFT%2$s) goto <min%3$d>;",
		"VUFD%1$s = VUFT%2$s;",
		"goto <end%3$d>;",
		"<min%3$d>",
		"VUFD%1$s = VUFS%1$s;",
		"<end%3$d>\n");

	private static final String MOVE_OPERATION = "VUFT%s = VUFS%s;\n";

	private static final Map<String, Function<InjectPayloadVu, String>>
		INSTRUCTIONS = getInstructionMap();
	private static final Map<String, String> OPERATIONS = getOperationMap();

	private SleighLanguage language;
	private SAXParser saxParser;
	protected long dest;

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

	// for testing use only
	protected final Function<InjectPayloadVu, String> getInstruction() {
		return INSTRUCTIONS.get(name);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		Address vf0Address = program.getRegister(VEC_ZERO).getAddress();
		if (!INSTRUCTIONS.containsKey(getName())) {
			return new PcodeOp[0];
		}
		SleighLanguage l = language;
		String translateSpec = l.buildTranslatorTag(l.getAddressFactory(),
			l.getUniqueBase(), l.getSymbolTable());
		PcodeParser parser = null;
		try {
			parser = new PcodeParser(translateSpec);
		}
		catch (JDOMException e1) {
			Msg.error(this, e1);
			return new PcodeOp[0];
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
		dest = con.inputlist.get(0).getOffset();
		Function<InjectPayloadVu, String> function = INSTRUCTIONS.get(name);
		StringBuilder pcodeTextBuilder = new StringBuilder();
		for (int i = 1; i < con.inputlist.size(); i++) {
			if (con.inputlist.get(i).getSize() == 0x10) {
				if (vf0Address.equals(con.inputlist.get(i).getAddress())) {
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
		VuErrorHandler errHandler = new VuErrorHandler();
		XmlPullParser xmlParser = null;
		try {
			xmlParser =
				XmlPullParserFactory.create(constructTplXml, sourceName, errHandler, false);
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
		if (errHandler.e != null) {
			throw new SleighException("pcode compiler returned invalid xml " + sourceName,
				errHandler.e);
		}
		setTemplate(constructTpl);
		SleighParserContext protoContext =
			new SleighParserContext(con.baseAddr, con.nextAddr, con.refAddr, con.callAddr);
		ParserWalker walker = new ParserWalker(protoContext);
		PcodeEmitObjects emit = new PcodeEmitObjects(walker);
		inject(con, emit);
		return emit.getPcodeOp();
	}

	private static String setZero(long dest, String register) {
		final int MAX_STRING_LENGTH = 119;
		StringBuilder builder = new StringBuilder(MAX_STRING_LENGTH);
		for(int i = 3; i >= 0; i--) {
			if (((dest >> i) & 1) == 1) {
				builder.append(String.format(
					SET_ZERO, register, VECTOR_DIRECTIONS[i], i == 0 ? 1 : 0));
			}
		}
		return builder.toString();
	}

	private static final String buildMac(int index, String name) {
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < 4; i++) {
			int ordinal = (i << 2) + index;
			switch(i) {
				case 0:
					// result == 0
					builder.append(
						String.format("vuMAC_32[%d,1] = (VUFD%s == 0);\n",
									  ordinal, VECTOR_DIRECTIONS[index]));
					break;
				case 1:
					// result < 0
					builder.append(
						String.format("vuMAC_32[%d,1] = (VUFD%s < 0);\n",
									  ordinal, VECTOR_DIRECTIONS[index]));
					break;
				case 2:
					// underflow
					if (name.contains("SUB")) {
						builder.append(
							String.format(NAN_COND, ordinal, VECTOR_DIRECTIONS[index]));
					} else {
						builder.append(String.format(CLEAR_MAC, ordinal));
					}
					break;
				case 3:
					// overflow
					if (name.contains("ADD")) {
						builder.append(
							String.format(NAN_COND, ordinal, VECTOR_DIRECTIONS[index]));
					} else {
						builder.append(String.format(CLEAR_MAC, ordinal));
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
			builder.append(String.format(CLEAR_MAC, (i << 2) + index));
		}
		return builder.toString();
	}

	private static String buildStatus() {
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < 4; i++) {
			int ordinal = i << 2;
			builder.append(String.format(
				STATUS_LOWER, i, ordinal++, ordinal++, ordinal++, ordinal));
		}
		for (int i = 6; i <= 9; i++) {
			builder.append(String.format(
				"vuStatus_32[%1$d,1] = vuStatus_32[%1$d,1] || vuStatus_32[%2$d,1];\n", i, i-6));
		}
		return builder.toString();
	}

	private static String getOperationText1(InjectPayloadVu self) {
		StringBuilder builder = new StringBuilder();
		String operation = OPERATIONS.get(self.name);
		for(int i = 3; i >= 0; i--) {
			if (((self.dest >> i) & 1) == 1) {
				builder.append(String.format(
					"VUFT%1$s = %2$s(VUFS%1$s);\n", VECTOR_DIRECTIONS[i], operation));
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
				builder.append(String.format("VUFD%1$s = VUFS%1$s %2$s VUFT%3$s;\n",
					VECTOR_DIRECTIONS[i], operation,
					broadcast ? "" : VECTOR_DIRECTIONS[i]))
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
				builder.append(
					String.format(
						"VUFD%1$s = vuACC%1$s %2$s VUFS%1$s f* VUFT%3$s;\n",
						VECTOR_DIRECTIONS[i], operation,
						broadcast ? "" : VECTOR_DIRECTIONS[i]))
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
					builder.append(String.format(
						"VUFT%s = *:4 (addr + %d);\n", VECTOR_DIRECTIONS[i], i << 2));
				}
			}
			return builder.toString();
	}

	private static String getStoreText(InjectPayloadVu self) {
		StringBuilder builder = new StringBuilder();
		for(int i = 3; i >= 0; i--) {
			if (((self.dest >> i) & 1) == 1) {
				builder.append(String.format(
					"*:4 (addr + %d) = VUFS%s;\n", i << 2, VECTOR_DIRECTIONS[i]));
			}
		}
		return builder.toString();
	}

	private static String getMaxText(InjectPayloadVu self) {
		boolean broadcast = self.name.endsWith(BROADCAST);
		StringBuilder builder = new StringBuilder();
		for(int i = 3; i >= 0; i--) {
			if (((self.dest >> i) & 1) == 1) {
				builder.append(String.format(
					MAX_OPERATION, VECTOR_DIRECTIONS[i],
					broadcast ? "" : VECTOR_DIRECTIONS[i], i));
			}
		}
		return builder.toString();
	}

	private static String getMinText(InjectPayloadVu self) {
		boolean broadcast = self.name.endsWith(BROADCAST);
		StringBuilder builder = new StringBuilder();
		for(int i = 3; i >= 0; i--) {
			if (((self.dest >> i) & 1) == 1) {
				builder.append(String.format(
					MIN_OPERATION, VECTOR_DIRECTIONS[i],
					broadcast ? "" : VECTOR_DIRECTIONS[i], i));
			}
		}
		return builder.toString();
	}

	private static String getMFIRText(InjectPayloadVu self) {
		StringBuilder builder = new StringBuilder();
		for(int i = 3; i >= 0; i--) {
			if (((self.dest >> i) & 1) == 1) {
				builder.append(String.format(
					"VUFT%s = sext(VUIS);\n", VECTOR_DIRECTIONS[i]));
			}
		}
		return builder.toString();
	}

	private static String getMoveText(InjectPayloadVu self) {
		StringBuilder builder = new StringBuilder();
		boolean broadcast = self.name.endsWith(BROADCAST);
		for(int i = 3; i >= 0; i--) {
			if (((self.dest >> i) & 1) == 1) {
				builder.append(String.format(
					MOVE_OPERATION, VECTOR_DIRECTIONS[i],
					broadcast ? "" : VECTOR_DIRECTIONS[i]));
			}
		}
		return builder.toString();
	}

	private static String getMoveRotateText(InjectPayloadVu self) {
		StringBuilder builder = new StringBuilder();
		for(int i = 3; i >= 0; i--) {
			if (((self.dest >> i) & 1) == 1) {
				builder.append(String.format(
					MOVE_OPERATION, VECTOR_DIRECTIONS[i], VECTOR_DIRECTIONS[i-1 < 0 ? 3 : i-1]));
			}
		}
		return builder.toString();
	}

	private static String clearRegister(InjectPayloadVu self) {
		StringBuilder builder = new StringBuilder();
		for(int i = 3; i >= 0; i--) {
			if (((self.dest >> i) & 1) == 1) {
				builder.append(String.format(SET_ZERO, VUFD, VECTOR_DIRECTIONS[i], 0));
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

	private static class VuErrorHandler implements ErrorHandler {

		private SAXParseException e;

		@Override
		public void warning(SAXParseException e) throws SAXException {
			Msg.warn(this, e.getMessage());
		}

		@Override
		public void fatalError(SAXParseException e) throws SAXException {
			this.e = e;
		}

		@Override
		public void error(SAXParseException e) throws SAXException {
			this.e = e;
		}
	}
}
