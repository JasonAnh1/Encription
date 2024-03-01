package com.jason;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws Exception {
        // Question 1 AES encription
//        String originalString = "Plain text need to encode";
//
//
//        String encryptedString
//                = AES.encrypt(originalString);
//
//        // Call decryption method
//        String decryptedString
//                = AES.decrypt(encryptedString);
//
//        // Print all strings
//        System.out.println(originalString);
//        System.out.println(encryptedString);
//        System.out.println(decryptedString);


        // Question 2 Hibrid encription



        // @Client: Generate Public and Private Key

        Map<String, Object> keys = HibridEncryption.getRSAKeys();
        PrivateKey privateKey = (PrivateKey) keys.get("private");
        PublicKey publicKey = (PublicKey) keys.get("public");
        System.out.println("Key Pairs generated on client-side");


        //@Client: Sent public key to the server and save the private key on
        // client local storage

        System.out.println("private-key store on client-side");
        System.out.println("sent public-key  to server-side");


        // @Server: Server will generate a secure random aes_key

        String secure_random_aes_key = HibridEncryption.secureRandomString();
        System.out.println("Generate Secure Random AES key on server-side");


        // @Server:Ecrypt the AES key using public key and store the AES key on
        // server-side.

        String encrptText = HibridEncryption.encryptMessageUsingPublic
                (secure_random_aes_key, privateKey);
        System.out.println("Encrypted the AES key using public key");
        System.out.println("AES key stored on server");


        // @Server:Sent encrypted AES key to client-side

        System.out.println("Sent encrypted AES key to client-side");


        // @Client: Decrypt the encrypted AES key using private key

        String aesKey = HibridEncryption.decryptMessagePrivateKey
                (encrptText, publicKey);
        System.out.println("AES key successfully decrypted");


        // @Client:Encrypt the secrets using AES key and sent it to server-side

        String enc = HibridEncryption.encrypt("plain text 123", aesKey);
        System.out.println("Secret succesfully encrypted");
        System.out.println("Encrypted secret successfully sent to server");


        // @Server:Decrypt the secret using AES key

        String secret = HibridEncryption.decrypt(enc, aesKey);
        System.out.println("Successfully decrypted, Your secret is:" + secret);



    }
}
