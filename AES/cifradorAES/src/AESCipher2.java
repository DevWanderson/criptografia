import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class AESCipher2 {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Escolha um modo de operação 'ECB, CBC, CFB, OFB ou CTR'");
        String mode = scanner.nextLine();

        System.out.println("Escolha o tamanho da chave 128, 192 ou 256");
        String keySize = scanner.nextLine();

        System.out.println("Escolha uma operação 'E' para cifrar (encrypt) e 'D' para decifrar (decrypt)");
        String operation = scanner.nextLine();

        System.out.println("Uma string com o texto claro (para cifrar) ou o texto cifrado (para decifrar)");
        String inputText = scanner.nextLine();

        byte[] key = getKey(keySize);

        byte [ ] iv = new byte[16]; //Zerar iv
        AESCipher2 aesCipher = new AESCipher2();
        String result = aesCipher.performAESEncryption(mode, key, iv, operation, inputText);
        System.out.println("Result: " + result);
        }

    private String performAESEncryption(String mode, byte[] key, byte[] iv, String operation, String inputText) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/" + mode + "/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        if (operation.equals("E")) {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] encrypted = cipher.doFinal(inputText.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte [] decodedValue = Base64.getDecoder().decode(inputText);
            byte [] decrypted = cipher.doFinal(decodedValue);
            return new String(decrypted);
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
                throw new IllegalArgumentException("Invalid key size.");
        }
    }

    private static byte[] hexStringToByteArray(String s) {
        int leng = s.length();
        byte[] data = new byte[leng / 2];
        for (int i = 0; i < leng; i+=2){
            data[i / 2] = (byte)  ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}