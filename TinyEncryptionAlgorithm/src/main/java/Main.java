import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * The Main class contains the TEA (Tiny Encryption Algorithm) cipher implementation
 * along with PKCS7 padding and depadding methods.
 */
public class Main {
    static final int ROUNDS = 32;
    static final int BLOCK_SIZE = 8;
    private static final int INT_BLOCK_SIZE = 4;
    static final int LEFT_SHIFT = 4;
    static final int RIGHT_SHIFT = 5;
    static final int DELTA = 0x9e3779b9;

    /**
     * The main method demonstrates the usage of the TEA cipher with PKCS7 padding and depadding.
     *
     * @param args The command-line arguments (not used in this example).
     */
    public static void main(String[] args) {
        String inputFile = "input_file.txt";
        String outputFile = "output_file.txt";

        byte[] originalBytes = readBytesFromFile(inputFile);
        System.out.println(Arrays.toString(originalBytes));

        int[] key = { Integer.parseInt(args[0]),
                Integer.parseInt(args[1]),
                Integer.parseInt(args[2]),
                Integer.parseInt(args[3])
        };

        String mode = args[4];

        if( mode.equals("ENCRYPT") ){
            // Encrypt the content of the input file and write to encrypted file
            byte[] encryptedBytes = encryptTEACipherChain(originalBytes, key);
            writeBytesToFile(encryptedBytes, outputFile);
        } else if( mode.equals("DECRYPT") ){
            // Decrypt the content of the encrypted file and write to decrypted file
            byte[] decryptedBytes = decryptTEACipherChain(originalBytes, key);
            writeBytesToFile(decryptedBytes, outputFile);
        } else {
            System.out.println("Mode is not valid");
            System.exit(-1);
        }

        System.out.println("Encryption or decryption complete.");
    }

    /**
     * Encrypts the given input using the TEA cipher with PKCS7 padding.
     *
     * @param input The input bytes to be encrypted.
     * @param key   The key used for encryption.
     * @return The encrypted bytes.
     */
    public static byte[] encryptTEACipherChain(byte[] input, int[] key) {
        byte[] paddedInput = addPKCS7Padding(input);
        int numBlocks = paddedInput.length / BLOCK_SIZE;
        byte[] result = new byte[paddedInput.length];
        byte[] previousResult = new byte[paddedInput.length];

        for (int block = 0; block < numBlocks; block++) {

            int blockStart = block * BLOCK_SIZE;
            int v0 = ByteBuffer.wrap(paddedInput, blockStart, INT_BLOCK_SIZE).getInt();
            int v1 = ByteBuffer.wrap(paddedInput, blockStart + INT_BLOCK_SIZE, INT_BLOCK_SIZE).getInt();

            int sum = 0;
            for (int i = 0; i < ROUNDS; i++) {
                sum += DELTA;
                v0 += ((v1 << LEFT_SHIFT) + key[0]) ^ (v1 + sum) ^ ((v1 >>> RIGHT_SHIFT) + key[1]);
                v1 += ((v0 << LEFT_SHIFT) + key[2]) ^ (v0 + sum) ^ ((v0 >>> RIGHT_SHIFT) + key[3]);
            }

            if (block != 0) {
                v0 ^= previousResult[0];
                v1 ^= previousResult[1];
            }

            previousResult = new byte[paddedInput.length];
            ByteBuffer.wrap(previousResult, blockStart, BLOCK_SIZE).putInt(v0).putInt(v1);
            ByteBuffer.wrap(result, blockStart, BLOCK_SIZE).putInt(v0).putInt(v1);
        }

        return result;
    }

    /**
     * Decrypts the given cipher bytes using the TEA cipher with PKCS7 depadding.
     *
     * @param cipherBytes The cipher bytes to be decrypted.
     * @param key         The key used for decryption.
     * @return The decrypted bytes.
     */
    public static byte[] decryptTEACipherChain(byte[] cipherBytes, int[] key) {
        int numBlocks = cipherBytes.length / BLOCK_SIZE;
        byte[] result = new byte[cipherBytes.length];
        byte[] previousResult = new byte[cipherBytes.length];

        for (int block = 0; block < numBlocks; block++) {
            int blockStart = block * BLOCK_SIZE;
            int v0 = ByteBuffer.wrap(cipherBytes, blockStart, INT_BLOCK_SIZE).getInt();
            int v1 = ByteBuffer.wrap(cipherBytes, blockStart + INT_BLOCK_SIZE, INT_BLOCK_SIZE).getInt();

            if (block != 0) {
                v0 ^= previousResult[0];
                v1 ^= previousResult[1];
            }

            previousResult = new byte[cipherBytes.length];
            ByteBuffer.wrap(previousResult, blockStart, BLOCK_SIZE).putInt(v0).putInt(v1);

            long sum = DELTA * ROUNDS;
            for (int i = 0; i < ROUNDS; i++) {
                v1 -= ((v0 << LEFT_SHIFT) + key[2]) ^ (v0 + sum) ^ ((v0 >>> RIGHT_SHIFT) + key[3]);
                v0 -= ((v1 << LEFT_SHIFT) + key[0]) ^ (v1 + sum) ^ ((v1 >>> RIGHT_SHIFT) + key[1]);
                sum -= DELTA;
            }

            ByteBuffer.wrap(result, blockStart, BLOCK_SIZE).putInt(v0).putInt(v1);
        }

        return removePKCS7Padding(result);
    }

    /**
     * Adds PKCS7 padding to the input bytes.
     *
     * @param input The input bytes to be padded.
     * @return The padded bytes.
     */
    public static byte[] addPKCS7Padding(byte[] input) {
        int paddingLength = BLOCK_SIZE - (input.length % BLOCK_SIZE);
        byte[] padded = Arrays.copyOf(input, input.length + paddingLength);
        Arrays.fill(padded, input.length, padded.length, (byte) paddingLength);
        return padded;
    }

    /**
     * Removes PKCS7 padding from the given padded bytes.
     *
     * @param paddedBytes The padded bytes to be depadded.
     * @return The depadded bytes.
     */
    public static byte[] removePKCS7Padding(byte[] paddedBytes) {
        int paddingLength = paddedBytes[paddedBytes.length - 1] & 0xFF;
        if (paddingLength > 0 && paddingLength <= paddedBytes.length) {
            return Arrays.copyOfRange(paddedBytes, 0, paddedBytes.length - paddingLength);
        }
        return paddedBytes;
    }

    /**
     * Reads the contents of a file and returns them as a byte array.
     *
     * @param fileName The name of the file to be read.
     * @return A byte array containing the contents of the file, or {@code null} if an error occurs.
     */
    public static byte[] readBytesFromFile(String fileName) {
        try (FileInputStream inputStream = new FileInputStream(fileName)) {
            return inputStream.readAllBytes();
        } catch (IOException e) {
            System.err.println("Error reading from file: " + e.getMessage());
            return null;
        }
    }

    /**
     * Writes the given byte array to a file.
     *
     * @param data     The byte array to be written to the file.
     * @param fileName The name of the file to which the data will be written.
     */
    public static void writeBytesToFile(byte[] data, String fileName) {
        try (FileOutputStream outputStream = new FileOutputStream(fileName)) {
            outputStream.write(data);
            System.out.println("Bytes successfully written to file.");
        } catch (IOException e) {
            System.err.println("Error writing to file: " + e.getMessage());
        }
    }

}
