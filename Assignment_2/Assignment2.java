import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.PrintWriter;
import java.io.IOException;
import java.io.FileReader;
import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.Key;

public class Assignment2 {

    public static void main(String [] args) throws IOException {
        BigInteger p;
        BigInteger q;
        BigInteger n;
        BigInteger phin;
        BigInteger e = new BigInteger("65537");
        SecureRandom random = new SecureRandom();
        BigInteger[] exclidean;

        byte[] file_in_bytes = Files.readAllBytes(Paths.get(args[0]));
        byte[] hashed_file = hash_secret(file_in_bytes);
        BigInteger file_hashed = new BigInteger(1, hashed_file);

        do {
            p = BigInteger.probablePrime(512, random);
            q = BigInteger.probablePrime(512, random);
            n = p.multiply(q);
            phin = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
            exclidean = Exgcd(e,phin);
        } while (!(exclidean[0].equals(BigInteger.ONE)));
        //Write N to Modulus.txt
        
        PrintWriter writer = new PrintWriter("Modulus.txt", "UTF-8");
        writer.println(n.toString(16));
        writer.close();

        BigInteger d = Exgcd(e, phin)[1];

        BigInteger decryMeth = decryption(d, p, q, file_hashed);

        System.out.println(decryMeth.toString(16));
    }

    public static BigInteger decryption(BigInteger d, BigInteger p, BigInteger q, BigInteger filehashed) {
        // Using Chinese remainder therom

        BigInteger a = getModExp(filehashed, d.mod(p.subtract(BigInteger.ONE)), p);
        BigInteger b = getModExp(filehashed, d.mod(q.subtract(BigInteger.ONE)), q);

        BigInteger ans = Exgcd(q, p)[1];

        return b.add(q.multiply((ans.multiply(a.subtract(b))).mod(p)));
    }

    public static byte[] hash_secret(byte[] file_in_bytes) {
        byte[] hash;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            hash = digest.digest(file_in_bytes);
        }
        catch (Exception error){
            throw new RuntimeException(error);
        }
        return hash;
    }

    public static BigInteger getModExp(BigInteger a, BigInteger x, BigInteger n){
        /*
        Code from the first assignment
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

    public static BigInteger[] Exgcd(BigInteger a, BigInteger b){
        // Returns a list, The xgcd[0]                                                                                               shows if the two numbers given are relatively prime or not.
        // The two numbers are are relatively prime if the greatest common divisior is 1.
        
        // xgcd[1] returns the result of the multiplicative inserve of two numbers using the
        // Extended Euclidean Greatest Common Divisor algorithm

        // xgcd[2] returns the result of the multiplicative inserve of the remaingning

        
        // If hit base case -> Start working backwords starting with the last remaineder
        // which should be one if they are relatively prime
        if(b.equals(BigInteger.ZERO)){
            return new BigInteger[]{a, BigInteger.ONE, BigInteger.ZERO};
        }

        BigInteger [] temp = Exgcd(b, a.mod(b));
        BigInteger relprime = temp[0];//If this is one then the numbers are relatively prime
        BigInteger multInv1 = temp[2];
        BigInteger multInv2 = temp[1].subtract((a.divide(b)).multiply(temp[2]));

        return new BigInteger[]{relprime, multInv1, multInv2};
    }
    
}