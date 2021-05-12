import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.IOException;
import java.io.FileReader;
import java.io.BufferedReader;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.Key;

public class Assignment1 {
    
    public static void main(String [] args) throws IOException, GeneralSecurityException{
 
        byte[] file_in_bytes = Files.readAllBytes(Paths.get(args[0]));
        byte[] padded_file = pad_file(file_in_bytes);

        String prime_modulus = "b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323";
        String generator = "44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68";
        String receivor_shared_value = "5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6238e6f6b76ece1f1b38ba4e210f61a2b84ef1b5dc4151e799485b2171fcf318f86d42616b8fd8111d59552e4b5f228ee838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15171cb861b367732460e3a9842b532761c16218c4fea51be8ea0248385f6bac0d";
        String my_secret_value = "005ea4c3a36ae476995213d30b3dbb0c304c2e52fce4c2af40a86a5d776f464c1877f9a7a805e7ba178b3a282fdd16f468a947838aabbfa054e10c229b86068acc81f3f9e8f947e1825896de3fa432e23524758cf3d0e1e84226130d7cd5c2656db6d7b2def8c648d2d083014dd1b65c21d1b1340ce53f26f607267ece66cb";
        
        BigInteger prime_modulus_bigint = new BigInteger(prime_modulus,16);
        BigInteger generator_bigint = new BigInteger(generator,16);
        BigInteger receivor_shared_value_bigint = new BigInteger(receivor_shared_value,16);        
        BigInteger secret_value_bigint = new BigInteger(my_secret_value,16);
        
        BigInteger shared_value = getModExp(generator_bigint, secret_value_bigint, prime_modulus_bigint);
        BigInteger shared_secret = getModExp(receivor_shared_value_bigint, secret_value_bigint, prime_modulus_bigint);
    
        byte[] hashed_secret = hash_secret(shared_secret);

        // Get IV From File
        BufferedReader br = new BufferedReader(new FileReader("IV.txt"));
        String iv = br.readLine();
        BigInteger initialization_vector_bigint = new BigInteger(iv, 16);
        byte[] initialization_vector = initialization_vector_bigint.toByteArray();
        initialization_vector = twos_complement(initialization_vector);

        byte[] encryptedPlaintext = aesEncyption(hashed_secret, padded_file, initialization_vector);
        
        // Testing encryption
        // byte[] encryptedtoDecrypt = decryptCiphertext(encryptedPlaintext, hashed_secret, initialization_vector);        
        // String value = new String(encryptedtoDecrypt, "UTF-8");
        // System.out.println(value);

        // Testing padding
        // System.out.println(pad_file(file_in_bytes).length);
        // System.out.println(Arrays.toString(pad_file(file_in_bytes)));

        // Output to Encryption File -> java Assignment1 Assignment1.class > Encryption.txt
        
        System.out.println(byteToHex(encryptedPlaintext));
    }

    public static String byteToHex(byte[] bytearray) {
        StringBuilder sb = new StringBuilder(bytearray.length * 2);
        for(byte a: bytearray){ 
            sb.append(String.format("%02x", a));
        }
        return sb.toString();
    }


    public static byte[] pad_file(byte[] file_in_bytes) {
        // 16 bytes == 128 bits
        
        int file_length = file_in_bytes.length;
        int padding_needed = 16 - file_in_bytes.length % 16;
        byte[] padded_file;
        if (padding_needed == 16) {
            padded_file = new byte[file_in_bytes.length+16];
        }
        else {
            padded_file = new byte[file_in_bytes.length+padding_needed];
        }
        System.arraycopy(file_in_bytes,0,padded_file,0,file_length);
        padded_file[file_length] = (byte) 128;   // 128 -> 1000 0000

        return padded_file;
    }

    public static BigInteger getModExp(BigInteger a, BigInteger x, BigInteger n){
        /*
        Code in notes
        y = 1
        for i = k-1 downto 0 do 
            y = (y*y) mod n
            if xi = 1 then y = (y*a) mod n end if
        end for
         */
        BigInteger result = BigInteger.valueOf(1);
        int i;
        for(i = 0; i < x.bitLength(); i++){
            result = result.multiply(result).mod(n);
            if (x.testBit(i)) {
                result = result.multiply(a).mod(n);
            }
        }
        return result;

    }

    // ~~~~~~For testing Encryption~~~~
    // public static byte[] decryptCiphertext(byte[] cipherBytes, byte[] AESkey, byte[] IV) throws GeneralSecurityException, UnsupportedEncodingException {
    //     Cipher decrypt = Cipher.getInstance("AES/CBC/NoPadding");
    //     Key key = new SecretKeySpec(AESkey, "AES");
    //     IvParameterSpec iv = new IvParameterSpec(IV);
    //     decrypt.init(Cipher.DECRYPT_MODE, key, iv);
    //     byte[] plainTextBytes = decrypt.doFinal(cipherBytes);
	// 	return plainTextBytes;
	// }

    public static byte[] aesEncyption(byte[] hashed_secret, byte[] file_in_bytes, byte[] ivector){
        byte[] encryptedData;
        IvParameterSpec iv = new IvParameterSpec(ivector);
        SecretKeySpec key = new SecretKeySpec(hashed_secret, "AES");
        try {

            Cipher ciph = Cipher.getInstance("AES/CBC/NoPadding");
            ciph.init(Cipher.ENCRYPT_MODE, key, iv);

            encryptedData = ciph.doFinal(file_in_bytes);
        }
        catch(Exception error) {
            throw new RuntimeException(error);
        }
        return encryptedData;
    }

    public static byte[] psuedoRandomNumberGenerator(int bits) {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[bits];
        random.nextBytes(bytes);
        return bytes;
    }

    public static byte[] hash_secret(BigInteger hashed_secret) {
        byte[] hash;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] secret = hashed_secret.toByteArray();
            hash = digest.digest(secret);
        }
        catch (Exception error){
            throw new RuntimeException(error);
        }
        hash = twos_complement(hash);
        return hash;
    }

    public static byte[] twos_complement(byte[] array) {
        if (array[0] == 0) {
            array = Arrays.copyOfRange(array, 1, array.length);
        }
        return array;
    }
}