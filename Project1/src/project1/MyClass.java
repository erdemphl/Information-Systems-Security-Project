package project1;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.HexFormat;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Paths;

public class MyClass {

	public static void main(String[] args) throws Exception {
		/* Create some necessary variables */
		HexFormat hexFormat = HexFormat.of(); // Create an HexFormat instance to convert byte arrays to hexadecimal strings
		BufferedWriter writer = new BufferedWriter(new FileWriter("output/output.txt"));
		
		
		/* Generate an RSA public-private key pair - Tested */
		KeyPairGenerator rsaKeyPairGenerator = KeyPairGenerator.getInstance("RSA");
		rsaKeyPairGenerator.initialize(1024);
		
		KeyPair rsaKeyPair = rsaKeyPairGenerator.generateKeyPair();
		PrivateKey keyAPrivate = rsaKeyPair.getPrivate();
		PublicKey keyAPublic = rsaKeyPair.getPublic();
		
		writer.write("Key A private:\n");
		writer.write(hexFormat.formatHex(keyAPrivate.getEncoded()).toUpperCase() + "\n");
		writer.write("\nKey A public:\n");
		writer.write(hexFormat.formatHex(keyAPublic.getEncoded()).toUpperCase() + "\n");

		
		/* Generate two ECDH public-private key pairs - Tested */
	    KeyPairGenerator ecdhKeyPairGenerator = KeyPairGenerator.getInstance("EC");
	    ecdhKeyPairGenerator.initialize(256);
	    
	    KeyPair ecdhKeyPair1 = ecdhKeyPairGenerator.generateKeyPair();
		PrivateKey keyBPrivate = ecdhKeyPair1.getPrivate();
		PublicKey keyBPublic = ecdhKeyPair1.getPublic();
		
	    KeyPair ecdhKeyPair2 = ecdhKeyPairGenerator.generateKeyPair();
		PrivateKey keyCPrivate = ecdhKeyPair2.getPrivate();
		PublicKey keyCPublic = ecdhKeyPair2.getPublic();
		
		writer.write("\nKey B private:\n");
		writer.write(hexFormat.formatHex(keyBPrivate.getEncoded()).toUpperCase() + "\n");
		writer.write("\nKey B public:\n");
		writer.write(hexFormat.formatHex(keyBPublic.getEncoded()).toUpperCase() + "\n");
		
		writer.write("\nKey C private:\n");
		writer.write(hexFormat.formatHex(keyCPrivate.getEncoded()).toUpperCase() + "\n");
		writer.write("\nKey C public:\n");
		writer.write(hexFormat.formatHex(keyCPublic.getEncoded()).toUpperCase() + "\n");
		
		
		/* Generate two symmetric keys K1 and K2 using a secure key derivation function - Tested */
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey key1 = keyGenerator.generateKey();
        
        keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey key2 = keyGenerator.generateKey();
		
		writer.write("\nKey 1:\n");
		writer.write(hexFormat.formatHex(key1.getEncoded()).toUpperCase() + "\n");
		
		writer.write("\nKey 2:\n");
		writer.write(hexFormat.formatHex(key2.getEncoded()).toUpperCase() + "\n");
		
		
		/* Encryption and decryption of K1 and K2 using RSA keys - Tested */
		// Encryption
		Cipher rsaEncryptCipherWithPublicKey = Cipher.getInstance("RSA");
		rsaEncryptCipherWithPublicKey.init(Cipher.ENCRYPT_MODE, keyAPublic);
		
		byte[] key1Encrypted = rsaEncryptCipherWithPublicKey.doFinal(key1.getEncoded());
		
		writer.write("\nKey 1 encrypted with Key A public:\n");
		writer.write(hexFormat.formatHex(key1Encrypted).toUpperCase() + "\n");
		
		byte[] key2Encrypted = rsaEncryptCipherWithPublicKey.doFinal(key2.getEncoded());
		
		writer.write("\nKey 2 encrypted with Key A public:\n");
		writer.write(hexFormat.formatHex(key2Encrypted).toUpperCase() + "\n");
		
		// Decryption
		Cipher rsaDecryptCipherWithPrivateKey = Cipher.getInstance("RSA");
		rsaDecryptCipherWithPrivateKey.init(Cipher.DECRYPT_MODE, keyAPrivate);
		
		byte[] key1Decrypted = rsaDecryptCipherWithPrivateKey.doFinal(key1Encrypted);
		
		writer.write("\nKey 1 decrypted:\n");
		writer.write(hexFormat.formatHex(key1Decrypted).toUpperCase() + "\n");
		
		byte[] key2Decrypted = rsaDecryptCipherWithPrivateKey.doFinal(key2Encrypted);
		
		writer.write("\nKey 2 decrypted:\n");
		writer.write(hexFormat.formatHex(key2Decrypted).toUpperCase() + "\n");
		
		
		/* Generate a symmetric key using ECDH key pairs - Tested */
	    KeyAgreement keyAgreement1 = KeyAgreement.getInstance("ECDH");
	    keyAgreement1.init(keyBPrivate);
	    keyAgreement1.doPhase(keyCPublic, true);
	    byte [] sharedSecret1 = keyAgreement1.generateSecret();
	    
	    KeyAgreement keyAgreement2 = KeyAgreement.getInstance("ECDH");
	    keyAgreement2.init(keyCPrivate);
	    keyAgreement2.doPhase(keyBPublic, true);
	    byte [] sharedSecret2 = keyAgreement2.generateSecret();
	    
	    writer.write("\nKey generated using key-B-private and key-C-public:\n");
	    writer.write(hexFormat.formatHex(sharedSecret1).toUpperCase() + "\n");
	    
	    writer.write("\nKey generated using key-C-private and key-B-public:\n");
	    writer.write(hexFormat.formatHex(sharedSecret2).toUpperCase() + "\n");
	    
	    byte[] key3 = sharedSecret1;
	    
	    /* Generate a digital signature of an image file and verify it - Tested */
	    byte[] messageBytes = Files.readAllBytes(Paths.get("src/myImage.jpg"));
	    
	    MessageDigest md = MessageDigest.getInstance("SHA-256");
	    byte[] messageHash = md.digest(messageBytes); // Message hash
	    writer.write("\nMessage digest H(m):\n");
	    writer.write(hexFormat.formatHex(messageHash).toUpperCase() + "\n");
	    
	    // Create the necessary cipher instances
		Cipher rsaEncryptCipherWithPrivateKey = Cipher.getInstance("RSA");
		rsaEncryptCipherWithPrivateKey.init(Cipher.ENCRYPT_MODE, keyAPrivate);
		
		Cipher rsaDecryptCipherWithPublicKey = Cipher.getInstance("RSA");
		rsaDecryptCipherWithPublicKey.init(Cipher.DECRYPT_MODE, keyAPublic);
		
		byte[] digitalSignature = rsaEncryptCipherWithPrivateKey.doFinal(messageHash); // Digital signature of the image
		writer.write("\nDigital signature:\n");
		writer.write(hexFormat.formatHex(digitalSignature).toUpperCase() + "\n");
		
		byte[] digitalSignatureDecrypted = rsaDecryptCipherWithPublicKey.doFinal(digitalSignature);
		writer.write("\nDigital signature decrypted with RSA public key:\n");
		writer.write(hexFormat.formatHex(digitalSignatureDecrypted).toUpperCase() + "\n");
		
		
		/* AES in CBC mode, 128 bit key, first iteration - Tested */
		SecureRandom random = new SecureRandom();
	    byte[] iv = new byte[16];
	    random.nextBytes(iv);
	    IvParameterSpec ivSpec = new IvParameterSpec(iv);
	    
	    writer.write("\nIV for AES in CBC mode, 128 bit key, first iteration:\n");
	    writer.write(hexFormat.formatHex(iv).toUpperCase() + "\n");
	    
        Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, key1, ivSpec);
        
        long startTime = System.currentTimeMillis();
        byte[] messageBytesEncrypted = encryptCipher.doFinal(messageBytes);
        long endTime = System.currentTimeMillis();
        
        writer.write("\nTime elapsed for encryption for AES in CBC mode, 128 bit key, first iteration:\n");
        writer.write((endTime - startTime) + " ms\n");
        
        FileOutputStream outputStream = new FileOutputStream("output/AES-CBC-128-First.txt");
		outputStream.write(messageBytesEncrypted);
		outputStream.close();
		
        Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decryptCipher.init(Cipher.DECRYPT_MODE, key1, ivSpec);
        
        byte[] messageBytesDecrypted = decryptCipher.doFinal(messageBytesEncrypted);
        
        outputStream = new FileOutputStream("output/AES-CBC-128-First-Decrypted.jpg");
		outputStream.write(messageBytesDecrypted);
		outputStream.close();
		
		
		/* AES in CBC mode, 128 bit key, second iteration - Tested */
	    random.nextBytes(iv);
	    ivSpec = new IvParameterSpec(iv);
	    
	    writer.write("\nIV for AES in CBC mode, 128 bit key, second iteration:\n");
	    writer.write(hexFormat.formatHex(iv).toUpperCase() + "\n");
	    
        encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, key1, ivSpec);
        
        startTime = System.currentTimeMillis();
        messageBytesEncrypted = encryptCipher.doFinal(messageBytes);
        endTime = System.currentTimeMillis();
        
        writer.write("\nTime elapsed for encryption for AES in CBC mode, 128 bit key, second iteration:\n");
        writer.write((endTime - startTime) + " ms\n");
        
        outputStream = new FileOutputStream("output/AES-CBC-128-Second.txt");
		outputStream.write(messageBytesEncrypted);
		outputStream.close();
		
        decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decryptCipher.init(Cipher.DECRYPT_MODE, key1, ivSpec);
        
        messageBytesDecrypted = decryptCipher.doFinal(messageBytesEncrypted);
        
        outputStream = new FileOutputStream("output/AES-CBC-128-Second-Decrypted.jpg");
		outputStream.write(messageBytesDecrypted);
		outputStream.close();
		
		
		/* AES in CBC mode, 256 bit key - Tested */
	    random.nextBytes(iv);
	    ivSpec = new IvParameterSpec(iv);
	    
	    writer.write("\nIV for AES in CBC mode, 256 bit key:\n");
	    writer.write(hexFormat.formatHex(iv).toUpperCase() + "\n");
	    
        encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, key2, ivSpec);
        
        startTime = System.currentTimeMillis();
        messageBytesEncrypted = encryptCipher.doFinal(messageBytes);
        endTime = System.currentTimeMillis();
        
        writer.write("\nTime elapsed for encryption for AES in CBC mode, 256 bit key:\n");
        writer.write((endTime - startTime) + " ms\n");
        
        outputStream = new FileOutputStream("output/AES-CBC-256.txt");
		outputStream.write(messageBytesEncrypted);
		outputStream.close();
		
        decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decryptCipher.init(Cipher.DECRYPT_MODE, key2, ivSpec);
        
        messageBytesDecrypted = decryptCipher.doFinal(messageBytesEncrypted);
        
        outputStream = new FileOutputStream("output/AES-CBC-256-Decrypted.jpg");
		outputStream.write(messageBytesDecrypted);
		outputStream.close();
		
		
		/* AES in CTR mode, 256 bit key - Tested */
		byte[] nonce = new byte[8];
		random.nextBytes(nonce);
		
		iv = new byte[16];
		System.arraycopy(nonce, 0, iv, 0, nonce.length);
	    ivSpec = new IvParameterSpec(iv);
	    
	    writer.write("\nIV for AES in CTR mode, 256 bit key (Nonce is the first 64 bits):\n");
	    writer.write(hexFormat.formatHex(iv).toUpperCase() + "\n");
	    
        encryptCipher = Cipher.getInstance("AES/CTR/NoPadding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, key2, ivSpec);
        
        startTime = System.currentTimeMillis();
        messageBytesEncrypted = encryptCipher.doFinal(messageBytes);
        endTime = System.currentTimeMillis();
        
        writer.write("\nTime elapsed for encryption for AES in CTR mode, 256 bit key:\n");
        writer.write((endTime - startTime) + " ms\n");
        
        outputStream = new FileOutputStream("output/AES-CTR-256.txt");
		outputStream.write(messageBytesEncrypted);
		outputStream.close();
		
        decryptCipher = Cipher.getInstance("AES/CTR/NoPadding");
        decryptCipher.init(Cipher.DECRYPT_MODE, key2, ivSpec);
        
        messageBytesDecrypted = decryptCipher.doFinal(messageBytesEncrypted);
        
        outputStream = new FileOutputStream("output/AES-CTR-256-Decrypted.jpg");
		outputStream.write(messageBytesDecrypted);
		outputStream.close();
		
		
		/* Generate a message authentication code of a text message - Tested */
		byte[] textMessageBytes = Files.readAllBytes(Paths.get("src/myText.txt"));
		
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(new SecretKeySpec(key3, "HmacSHA256"));
		
		byte[] textMessageMac = mac.doFinal(textMessageBytes);
		
		writer.write("\nMAC of the text message:\n");
		writer.write(hexFormat.formatHex(textMessageMac).toUpperCase() + "\n");
		
		
		/* Apply HMAC-256 to K2 to generate a new 256-bit key - Tested */
		byte[] newKey = mac.doFinal(key2.getEncoded());
		
		writer.write("\nNew key generated by applying HMAC-256 to K2:\n");
		writer.write(hexFormat.formatHex(newKey).toUpperCase() + "\n");
		
		writer.close();
	}
	
}
