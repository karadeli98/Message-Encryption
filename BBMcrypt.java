
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;

public class BBMcrypt {
	private static String[][] Desboxes = new String[4][16];
	private static String mode;
	private static String keyFile;
	private static String inputFile;
	private static String outputFile;
	private static String enc_decMode;

	public static void main(String[] args) throws IOException {

		Desboxes[0][0] = "0010";
		Desboxes[0][1] = "1100";
		Desboxes[0][2] = "0100";
		Desboxes[0][3] = "0001";
		Desboxes[0][4] = "0111";
		Desboxes[0][5] = "1010";
		Desboxes[0][6] = "1011";
		Desboxes[0][7] = "0110";
		Desboxes[0][8] = "1000";
		Desboxes[0][9] = "0101";
		Desboxes[0][10] = "0011";
		Desboxes[0][11] = "1111";
		Desboxes[0][12] = "1101";
		Desboxes[0][13] = "0000";
		Desboxes[0][14] = "1110";
		Desboxes[0][15] = "1001";

		Desboxes[1][0] = "1110";
		Desboxes[1][1] = "1011";
		Desboxes[1][2] = "0010";
		Desboxes[1][3] = "1100";
		Desboxes[1][4] = "0100";
		Desboxes[1][5] = "0111";
		Desboxes[1][6] = "1101";
		Desboxes[1][7] = "0001";
		Desboxes[1][8] = "0101";
		Desboxes[1][9] = "0000";
		Desboxes[1][10] = "1111";
		Desboxes[1][11] = "1010";
		Desboxes[1][12] = "0011";
		Desboxes[1][13] = "1001";
		Desboxes[1][14] = "1000";
		Desboxes[1][15] = "0110";

		Desboxes[2][0] = "0100";
		Desboxes[2][1] = "0010";
		Desboxes[2][2] = "0001";
		Desboxes[2][3] = "1011";
		Desboxes[2][4] = "1010";
		Desboxes[2][5] = "1101";
		Desboxes[2][6] = "0111";
		Desboxes[2][7] = "1000";
		Desboxes[2][8] = "1111";
		Desboxes[2][9] = "1001";
		Desboxes[2][10] = "1100";
		Desboxes[2][11] = "0101";
		Desboxes[2][12] = "0110";
		Desboxes[2][13] = "0011";
		Desboxes[2][14] = "0000";
		Desboxes[2][15] = "1110";

		Desboxes[3][0] = "1011";
		Desboxes[3][1] = "1000";
		Desboxes[3][2] = "1100";
		Desboxes[3][3] = "0111";
		Desboxes[3][4] = "0001";
		Desboxes[3][5] = "1110";
		Desboxes[3][6] = "0010";
		Desboxes[3][7] = "1101";
		Desboxes[3][8] = "0110";
		Desboxes[3][9] = "1111";
		Desboxes[3][10] = "0000";
		Desboxes[3][11] = "1001";
		Desboxes[3][12] = "1010";
		Desboxes[3][13] = "0100";
		Desboxes[3][14] = "0101";
		Desboxes[3][15] = "0011";

		readCommandsLine(args); // Reading from Command line
		
		String inputText = readFile(inputFile);
		String Base64key = readFile(keyFile);
		
		byte[] decodeBytes = Base64.getDecoder().decode(Base64key);
		String decodedString = new String(decodeBytes);
		String key = decodedString;

		if (inputText.length() % 96 != 0) {

			inputText = inputText + padZero(96 - (inputText.length() % 96));
		}

		int stepNumber = inputText.length() / 96;
		
		String[] subPlainText = new String[stepNumber];
		
		for (int i = 0; i < stepNumber; i++) {
			int index = 96 * i;
			subPlainText[i] = inputText.substring(index, index + 96);
		}

		String outputText = "";
		if (mode.equals("enc")) {
			if (enc_decMode.equals("ECB")) { //ECB;
				for (int i = 0; i < stepNumber; i++) {
					String plainTextL = subPlainText[i].substring(0, 48);
					String plainTextR = subPlainText[i].substring(48, 96);
					outputText = outputText + enCyripton(key, plainTextL, plainTextR);
				}
			} else if (enc_decMode.equals("CBC")) { // CBC
				String iV = padOne();
				for (int i = 0; i < stepNumber; i++) {
					subPlainText[i] = makeExorOperantion(iV, subPlainText[i]);
					String plainTextL = subPlainText[i].substring(0, 48);
					String plainTextR = subPlainText[i].substring(48, 96);
					iV = enCyripton(key, plainTextL, plainTextR);
					outputText = outputText + iV;
				}
			} else if (enc_decMode.equals("OFB")) { // OFB
				String iV = padOne();
				for (int i = 0; i < stepNumber; i++) {
					String plainTextL = iV.substring(0, 48);
					String plainTextR = iV.substring(48, 96);
					iV = enCyripton(key, plainTextL, plainTextR);
					outputText = outputText + makeExorOperantion(iV, subPlainText[i]);
				}
			}
			
		} else {
			if (enc_decMode.equals("ECB")) {
				for (int i = 0; i < stepNumber; i++) {
					String plainTextL = subPlainText[i].substring(0, 48);
					String plainTextR = subPlainText[i].substring(48, 96);
					outputText = outputText + deCyripton(key, plainTextL, plainTextR);
				}
			} else if (enc_decMode.equals("CBC")) {
				String iV = padOne();
				for (int i = 0; i < stepNumber; i++) {
					String plainTextL = subPlainText[i].substring(0, 48);
					String plainTextR = subPlainText[i].substring(48, 96);
					outputText = outputText + makeExorOperantion(iV, deCyripton(key, plainTextL, plainTextR));
					iV = subPlainText[i];
				}

			} else if (enc_decMode.equals("OFB")) {
				String iV = padOne();
				for (int i = 0; i < stepNumber; i++) {
					String plainTextL = iV.substring(0, 48);
					String plainTextR = iV.substring(48, 96);
					iV = enCyripton(key, plainTextL, plainTextR);
					outputText = outputText + makeExorOperantion(iV, subPlainText[i]);
				}
			}
			
			
		}
		writeFile(outputText);

	}

	public static String readFile(String inputFile) throws IOException {
		FileReader fileReader = new FileReader(inputFile);
		String line;
		String fileString = "";

		BufferedReader br = new BufferedReader(fileReader);

		while ((line = br.readLine()) != null) {

			fileString = line;

		}

		br.close();
		return fileString;

	}

	public static void writeFile(String output) throws IOException {
		FileWriter fileReader = new FileWriter(outputFile);
		fileReader.write(output);
		fileReader.close();

	}

	public static void readCommandsLine(String args[]) {
		for (int i = 0; i < args.length; i++) {
			if (args[i].equals("-K")) {
				keyFile = args[i + 1];
			} else if (args[i].equals("-I")) {
				inputFile = args[i + 1];
			} else if (args[i].equals("-O")) {
				outputFile = args[i + 1];
			} else if (args[i].equals("-M")) {
				enc_decMode = args[i + 1];
			}
		}
		if (args[0].equals("enc")) {
			mode = "enc";
		} else {
			mode = "dec";
		}

	}

	public static String padZero(int mode) {
		String padString = "";

		for (int i = 0; i < mode; i++) {
			padString = padString + "0";

		}
		return padString;

	}

	public static String padOne() {
		String padString = "";

		for (int i = 0; i < 96; i++) {
			padString = padString + "1";

		}
		return padString;

	}

	public static String enCyripton(String key, String l, String r) {

		for (int i = 0; i < 10; i++) {

			String subKey = leftShiftOperationEnc(key, i + 1);
			String resulofScrambleFunc = makeScrambleFunction(r, subKey);
			String newRbits = makeExorOperantion(l, resulofScrambleFunc);
			l = r;
			r = newRbits;
		}
		return l + r;
	}

	public static String deCyripton(String key, String l, String r) {

		for (int i = 10; i > 0; i--) {

			String subKey = leftShiftOperationEnc(key, i);
			String resulofScrambleFunc = makeScrambleFunction(l, subKey);
			String newLbits = makeExorOperantion(r, resulofScrambleFunc);
			r = l;
			l = newLbits;
		}

		return l + r;
	}

	public static String leftShiftOperationEnc(String key, int shiftNumber) {

		char[] ca = key.toCharArray();
		for (int j = 0; j < shiftNumber; j++) {
			int lastindex = key.length() - 1;
			char end = ca[0];
			for (int i = 0; i < lastindex; i++) {
				ca[i] = ca[i + 1];
			}
			ca[lastindex] = end;
		}
		return permutedChoice(String.valueOf(ca), shiftNumber - 1);
	}

	public static String permutedChoice(String realKey, int step) {
		String subkey = "";
		if (step % 2 == 0) {
			for (int i = 0; i < realKey.length(); i = i + 2) {

				subkey = subkey + String.valueOf(realKey.charAt(i));
			}
		} else {
			for (int i = 1; i < realKey.length(); i = i + 2) {

				subkey = subkey + String.valueOf(realKey.charAt(i));
			}
		}
		return subkey;
	}

	public static String makeScrambleFunction(String inputRbits, String keyOfRound) {
		ArrayList<String> steps = new ArrayList<>(); // hold the 6*12 binary
		String result = ""; // return to main function 4*12
		int j = 0;
		for (int i = 0; i < inputRbits.length(); i++) { // generate 6*8
			j = j + 1;
			result = result + (inputRbits.charAt(i) ^ keyOfRound.charAt(i));
			if (j == 6) {
				steps.add(result);
				j = 0;
				result = "";
			}
		}

		int size = steps.size() / 2;
		for (int i = 0; i < size; i++) { // added 4*6 steps1 & steps2
			String a = steps.get(2 * i);
			String b = steps.get((2 * i) + 1);

			for (int k = 0; k < a.length(); k++) {
				result = result + (a.charAt(k) ^ b.charAt(k));
			}
			steps.add(result);
			result = "";
		}

		result = simplifyKey(steps); // send 72 bit and come 48 bit
		return permutaionFunction(result); // send 48 bit key to permutaion function ..
	}

	public static String simplifyKey(ArrayList<String> key) {
		String simpleKey = "";// 6 bit to 4 bit 4*12
		for (String partKey : key) {
			String row = String.valueOf(partKey.charAt(0)) + String.valueOf(partKey.charAt(5));
			String column = String.valueOf(partKey.charAt(1)) + String.valueOf(partKey.charAt(2))
					+ String.valueOf(partKey.charAt(3)) + String.valueOf(partKey.charAt(4));

			int numRow = convertBtoD(row);
			int numColumn = convertBtoD(column);

			simpleKey = simpleKey + Desboxes[numRow][numColumn];
		}
		return simpleKey;
	}

	public static int convertBtoD(String number) {
		int total = 0;
		int j = 0;
		for (int i = number.length() - 1; i >= 0; i--) {

			total = total + ((int) Math.pow(2, j)) * (Integer.parseInt(String.valueOf(number.charAt(i))));
			j = j + 1;
		}

		return total;
	}

	public static String permutaionFunction(String binary) {

		char[] ca = binary.toCharArray();
		for (int i = 0; i < binary.length() / 2; i++) {

			char template = ca[2 * i];
			ca[2 * i] = ca[(2 * i) + 1];
			ca[(2 * i) + 1] = template;
		}
		return String.valueOf(ca);
	}

	public static String makeExorOperantion(String inputL, String resultScramble) {

		String result = "";
		for (int i = 0; i < inputL.length(); i++) {

			result = result + (inputL.charAt(i) ^ resultScramble.charAt(i));
		}
		return result;
	}

}
