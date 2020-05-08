package testt;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


import java.util.Base64;;


public class TripleDES {

    String key;

    public TripleDES(String myEncryptionKey) {
        key = myEncryptionKey;
    }

    /** method that encrypt a string **/ 
    public String Encrypt(String unencryptedString) throws NoSuchAlgorithmException, UnsupportedEncodingException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
       
    	
    	/// hashing the key to get fixed length 128bit then get key with 24 byte length  
    	
    	//get instance of message digest from the preferred provider of md5 algorithm 
    	//md5 algorith produce 128 bit hash value of any string
    	MessageDigest md = MessageDigest.getInstance("md5");
    	md.update(key.getBytes("utf-8"));
    	
    	// get the hashing result which will be 16 byte = 128 bit 
        byte[] digestOfPassword = md.digest();
        
        
        
        // because we need 3 keys and each key is 8byte(64bit) so we need 24 byte for the keys 
        byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
        //System.out.println(keyBytes[18]); // == 0
        
        // assign value for the last 8 bytes 
        
        int i = 0 ;
        for (int j = 16; j < 24;j++) {
            keyBytes[j] = keyBytes[i++];
        }
        
        
        
        //Constructs a secret key from the given byte array of amy length
        SecretKey secretKey = new SecretKeySpec(keyBytes, "DESede");
        
        // chiper object for triple DES
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        
        //initialize the chip given the mode , keys
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] plainTextBytes = unencryptedString.getBytes("utf-8");
        byte[] buf = cipher.doFinal(plainTextBytes);
        
        // encode the result to 64 radix 
        byte[] base64Bytes = Base64.getEncoder().encode(buf);
        String base64EncryptedString = new String(base64Bytes);

        return base64EncryptedString;
    }

    
    
    
    /**Method To Decrypt An Ecrypted String*/
    public String Decrypt(String encryptedString) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if(encryptedString == null)
        {
            return "";
        }
        
        //decode the radix64 string to the original string 
        byte[] message = Base64.getDecoder().decode(encryptedString.getBytes("utf-8"));
        
        //get the keys 
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digestOfPassword = md.digest(key.getBytes("utf-8"));
        byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
        
        int i = 0 ;
        for (int j = 16; j < 24;j++) {
            keyBytes[j] = keyBytes[i++];
        }
        
        //decoding using the same chiper configuration and the same used key 
        SecretKey secretKey = new SecretKeySpec(keyBytes, "DESede");

        Cipher decipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        decipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] plainText = decipher.doFinal(message);

        return new String(plainText, "UTF-8");

    }

}