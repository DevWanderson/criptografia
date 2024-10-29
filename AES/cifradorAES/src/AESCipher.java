import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class AESCipher {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Escolha um modo de operação (ECB, CBC, CFB, OFB, CTR):");
        String mode = scanner.nextLine();

        System.out.println("Escolha o tamanho da chave (128, 192, 256):");
        String keySize = scanner.nextLine();

        System.out.println("Escolha uma operação ('E' para cifrar, 'D' para decifrar):");
        String operation = scanner.nextLine();

        System.out.println("Digite o texto a ser cifrado ou decifrado:");
        String inputText = scanner.nextLine();

        byte[] key = getKey(keySize);
        byte[] iv = new byte[16]; // IV zerado

        AESCipher aesCipher = new AESCipher();
        String result = aesCipher.performAESEncryption(mode, key, iv, operation, inputText);
        System.out.println("Resultado: " + result);
    }

    public String performAESEncryption(String mode, byte[] key, byte[] iv, String operation, String inputText) throws Exception {
        Cipher cipher;
        if (mode.equals("ECB")) {
            cipher = Cipher.getInstance("AES/" + mode + "/PKCS5Padding");
        } else {
            cipher = Cipher.getInstance("AES/" + mode + "/PKCS5Padding");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            if (operation.equalsIgnoreCase("E")) {
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), ivSpec);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), ivSpec);
            }
            if (operation.equalsIgnoreCase("E")) {
                byte[] encrypted = cipher.doFinal(inputText.getBytes());
                return Base64.getEncoder().encodeToString(encrypted);
            } else {
                byte[] decodedValue = Base64.getDecoder().decode(inputText);
                byte[] decrypted = cipher.doFinal(decodedValue);
                return new String(decrypted);
            }
        }
    }

    private static byte[] getKey(String keySize) {
        switch (keySize) {
            case "128":
                return hexStringToByteArray("637572736F63727970746F6772616679");
            case "192":
                return hexStringToByteArray("637572736F63727970746F6772616679637572736F637279");
            case "256":
                return hexStringToByteArray("637572736F63727970746F6772616679637572736F63727970746F6772616679");
            default:
                throw new IllegalArgumentException("Tamanho de chave inválido.");
        }
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
