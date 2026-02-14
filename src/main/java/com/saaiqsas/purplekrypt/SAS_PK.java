package com.saaiqsas.purplekrypt;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.SecureRandom;

import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.Random;


public class SAS_PK {
    protected static final byte VERSION_IDENTIFIER = 1;
    /*
        SAS_PK.java - API providing cryptographic operations for PurpleKrypt

        +------------------------------------------------------------------------------------------------------------+
        |                                                                                                            |
        |     @@@@@@@@                                                                                               |
        |    @        @                                                                                              |
        |    @        @       @@@@@@@                           @           @     @                            @     |
        |    @        @       @      @                          @           @    @                             @     |
        |    @                @      @  @    @   @ @@ @@@@@@    @    @@@    @   @     @ @@  @     @  @@@@@@  @@@@@   |
        |     @@@@@@@@@@      @      @  @    @   @@   @     @   @  @     @  @@@@@     @@     @    @  @     @   @     |
        |   @@@@@@@@@   @     @@@@@@@   @    @   @    @     @   @  @@@@@@@  @   @     @       @  @   @     @   @     |
        |   @       @   @     @         @    @   @    @     @   @  @        @    @    @        @ @   @     @   @     |
        |   @    @@@@   @     @          @@@@    @    @@@@@@    @   @@@@@   @     @   @         @    @@@@@@    @     |
        |   @    @      @                             @                                        @     @               |
        |    @@@@@@@@@@                               @                                     @@@      @               |
        |                                                                                                            |
        +------------------------------------------------------------------------------------------------------------+

        +---------------------------------------------------------------------------------------------------------------+
        |  PurpleKrypt project is founded and maintained by saaiqSAS (Saaiq Abdulla Saeed) [https://saaiqsas.github.io] |
        +---------------------------------------------------------------------------------------------------------------+


        SAS_PK.java (PurpleKrypt API) is Licensed under The MIT License
        +---------------------------------------------------------------------------------------------------------------+
        |    The MIT License (MIT)                                                                                      |
        |                                                                                                               |
        |    Copyright © 2025-Present Saaiq Abdulla Saeed                                                               |
        |                                                                                                               |
        |    Permission is hereby granted, free of charge, to any person obtaining a copy of this software              |
        |    and associated documentation files (the “Software”), to deal in the Software without restriction,          |
        |    including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,      |
        |    and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,      |
        |    subject to the following conditions:                                                                       |
        |                                                                                                               |
        |    The above copyright notice and this permission notice shall be included in all copies or substantial       |
        |    portions of the Software.                                                                                  |
        |                                                                                                               |
        |    THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT          |
        |    NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.    |
        |    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,    |
        |    WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE        |
        |    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                                                     |
        +---------------------------------------------------------------------------------------------------------------+
    */

    private static final int FILE_BUFFER_MAX_SIZE = 10240;    // 10KB chunks

    // Parameters for Argon2
    private static final int SALT_LENGTH_BYTES = 16;     // 128-bit salt
    private static final int KEY_LENGTH_BYTES = 32;      // 256-bit AES key
    private static final int ITERATIONS = 3;             // 1-5 recommended
    private static final int MEMORY_COST_KB = 65536;     // 64MB in KB
    private static final int PARALLELISM = 2;            // cores

    // Parameters for AES-256-GCM
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_SIZE_BITS = 256;        // bits
    private static final int GCM_IV_LENGTH_BYTES = 12;   // 96 bits (NIST recommended)
    private static final int GCM_TAG_LENGTH_BITS= 128;   // 128 bits (maximum)
    private static final int GCM_TAG_LENGTH_BYTES = GCM_TAG_LENGTH_BITS/8; // 128 bits (maximum)
    
    
    // Memory - Can be used to store static
    protected static SecretKey KEY;
    protected static File KEYFILE;
    protected static char[] PASSWORD;
    protected static Salt SALT = new Salt();

    private static boolean STOP_FLAG = false;

    private SAS_PK() {}

    protected static void test() {
        try {
            // Method used to test the API and can also be referred to as a API usage sample

            // Generate SecretKey
            SecretKey genK = generateKey();
            System.out.println("Generated Key: " + Arrays.toString(genK.getEncoded()));
            System.out.println("Generated Key: Length: " + genK.getEncoded().length);
            System.out.println("Generated Key: Algorithm: " + genK.getAlgorithm());

            // Produce a Salt
            Salt salt = new Salt();
            System.out.println("Salt: " + Arrays.toString(salt.getSalt()));
            System.out.println("Salt Length: " + salt.getSalt().length);

            // Just a Password
            char[] password = "hello".toCharArray();
            System.out.println("Password: "+ Arrays.toString(password));

            // Derive SecretKey from char[] password
            SecretKey derK = deriveKey(password, salt);
            System.out.println("Password after key derivation:  "+ Arrays.toString(password));
            System.out.println("Derived Key: " + Arrays.toString(derK.getEncoded()));
            System.out.println("Derived Key Length: " + derK.getEncoded().length);
            System.out.println("Derived Key Algorithm: " + derK.getAlgorithm());

            // Clear Salt
            salt.clearSalt();
            System.out.println("Salt (after clearing): " + Arrays.toString(salt.getSalt()));
            System.out.println("Salt Length (after clearing): " + salt.getSalt().length);

            // Random data and AAD
            byte[] data = {(byte) 120, (byte) -11, (byte) 65, (byte) 1, (byte) -76, (byte) 45, (byte) 21, (byte) 12, (byte) 97, (byte) 112, (byte) -12,};
            byte[] aad = {(byte) 1, (byte) 2, (byte) 3, (byte) 4};

            System.out.println("Original Data: " + Arrays.toString(data));
            System.out.println("Original Data Length: " + data.length);

            // Encrypt and Decrypt byte[]
            byte[] encrypted = encryptBytes(derK, data, aad);
            System.out.println("Encrypted Data: " + Arrays.toString(encrypted));
            System.out.println("Encrypted Data Length: " + encrypted.length);

            byte[] decrypted = decryptBytes(derK, encrypted, aad);
            System.out.println("Decrypted Data: " + Arrays.toString(decrypted));
            System.out.println("Decrypted Data Length: " + decrypted.length);

            // Wipe the keys
            wipeKey(genK);
            wipeKey(derK);

            File keySaveFile = new File("test/test_key.pkk");
            if (keySaveFile.exists()) {
                deleteFileSecurely(keySaveFile);
                System.out.println("PREVIOUS KEY FILE DELETED SECURELY");
            }

            boolean encrypt_key = true;

            // Generate password encrypted Keyfile
            SecretKey gK = generateKeyFile(keySaveFile, encrypt_key, password);
            System.out.println("KEY FILE GENERATED");

            // Extract existing Keyfile onto memory
            SecretKey eK = extractKeyFile(keySaveFile, password);
            System.out.println("KEY FILE EXTRACTED");

            // Check to see whether generated and extracted keys same
            if (gK.equals(eK) ) {
                System.out.println("KEYS SAME");
            } else {
                System.out.println("KEYS NOT SAME");
            }

            // Just random String Data
            String text = "hello how are you man!!";

            // Encrypt and Decrypt String using SecretKey
            System.out.println("Enc/Dec String with SecretKey");
            String enc_text = encryptString(gK,text,aad);
            String dec_text = decryptString(gK,enc_text,aad);

            System.out.println("Original  String: "+ text);
            System.out.println("Encrypted String: "+ enc_text);
            System.out.println("Decrypted String: "+ dec_text);

            // Encrypt and Decrypt String using char[] Password
            System.out.println("Enc/Dec String with Password");
            String enc_text2 = encryptString(password,text,aad);
            String dec_text2 = decryptString(password,enc_text2,aad);

            System.out.println("Original  String: "+ text);
            System.out.println("Encrypted String: "+ enc_text2);
            System.out.println("Decrypted String: "+ dec_text2);


            String testFile1 = "test/test_file.jpeg";
            String testFile1EncOut = "test/test_file_enc.jpeg";

            String testFile2 = "test/test_file_2.jpeg";
            String testFile2EncOut = "test/test_file_2_enc.jpeg";

            String testFileDecOutputDir = "test/test_file_dec/";

            System.out.println("ENCRYPTING FILE (SecretKey)");
            double s1 = System.nanoTime();
            // Encrypt file
            encryptFile(gK,null,new File(testFile1),new File(testFile1EncOut),aad,true);
            double e1 = System.nanoTime();
            System.out.println("DONE ENCRYPTING FILE IN "+(e1-s1)+"ns");

            System.out.println("DECRYPTING FILE (SecretKey)");
            double s2 = System.nanoTime();
            // Decrypt file
            decryptFile(gK,null,new File(testFile1EncOut),new File(testFileDecOutputDir),aad);
            double e2 = System.nanoTime();
            System.out.println("DONE DECRYPTING FILE IN "+(e2-s2)+"ns");

            System.out.println("ENCRYPTING FILE (PASSWORD ONLY)");
            s1 = System.nanoTime();
            encryptFile(null,password,new File(testFile2),new File(testFile2EncOut),aad, true);
            e1 = System.nanoTime();
            System.out.println("DONE ENCRYPTING FILE IN "+(e1-s1)+"ns");

            System.out.println("DECRYPTING FILE (PASSWORD ONLY)");
            s2 = System.nanoTime();
            decryptFile(null,password,new File(testFile2EncOut),new File(testFileDecOutputDir),aad);
            e2 = System.nanoTime();
            System.out.println("DONE DECRYPTING FILE IN "+(e2-s2)+"ns");



        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    // ----- Prep for finishing up methods -----
    protected static void clearMemory(boolean keepKey, boolean keepPassword) {
        if (!keepKey && KEY != null) {
            wipeKey(KEY);
        }
        if (!keepPassword && PASSWORD != null) {
            wipeArray(PASSWORD);
        }
        KEYFILE = null;
        SALT.clearSalt();
    }

    protected static void stopAllProcesses() {
        STOP_FLAG = true;
        clearMemory(false,false);
    }

    // ----- AAD related method -----
    protected static byte[] generatePkAadIdFile(File saveFile) {
        // generates a file containing random 32 bytes that can be used as a unique ID and as AAD
        if (saveFile.exists()) { return null;}
        try (FileOutputStream fileWrite = new FileOutputStream(saveFile)){
            SecureRandom sr = SecureRandom.getInstanceStrong();
            byte[] id = new byte[32]; // 256 bits
            sr.nextBytes(id);
            fileWrite.write(id);
            return id;
        } catch (Exception e) {return null;}
    }

    // ----- Key related methods -----
    protected static SecretKey generateKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(KEY_SIZE_BITS, SecureRandom.getInstanceStrong());
            SecretKey key = keyGen.generateKey();
            validateKey(key);
            return key;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    protected static SecretKey deriveKey(char[] password, Salt salt) {
        // returns secret key derived from password using argon2id
        Objects.requireNonNull(password, "Password cannot be null");
        Objects.requireNonNull(salt, "Salt cannot be null");

        try {
            final Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withSalt(salt.getSalt())
                    .withIterations(ITERATIONS)
                    .withMemoryAsKB(MEMORY_COST_KB)
                    .withParallelism(PARALLELISM)
                    .build();

            final Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(params);

            final byte[] rawKey = new byte[KEY_LENGTH_BYTES];
            generator.generateBytes(password, rawKey);

            return new SecretKeySpec(rawKey, "AES");
        } catch (Exception e) {
            throw new SecurityException("Key derivation failed", e);
        }
    }

    protected static SecretKey generateKeyFile(File saveFile, boolean encryptKey, char[] password) throws Exception {
        // Generates a key file and returns the SecretKey stored in the keyfile.
        // DO NOTE THAT THE KEYFILE WILL NOT CONTAIN METADATA TO KNOW WHETHER IT IS PASSWORD ENCRYPTED.
        if (!saveFile.getName().endsWith(".pkk")) { throw new Exception("Unexpected Keyfile Extension");}
        if (saveFile.exists()) { throw new Exception("File Already Exists");}

        if (saveFile.createNewFile()) {
            FileOutputStream fileWrite = new FileOutputStream(saveFile);

            byte[] rawKey;
            Salt s = new Salt();

            SecretKey gk = generateKey();
            if (encryptKey) {
                if (password == null) { throw new Exception("No Password Passed");}

                SecretKey dk = deriveKey(password, s);

                rawKey = encryptBytes(dk, gk.getEncoded(), intToByteArray(VERSION_IDENTIFIER));
                wipeKey(dk);

            } else {
                rawKey = gk.getEncoded();
            }

            // Writing version_id password_salt and key (encrypted indicator byte removed for security)
            fileWrite.write(VERSION_IDENTIFIER);                 // 1 byte
            fileWrite.write(s.getSalt());                        // 16 bytes
            fileWrite.write(rawKey);                             // 32 bytes + ( 16 + 12 bytes [IV + AuthTag] if encrypted )

            if (!encryptKey) {
                byte[] rand = new byte[16+12]; // fake [IV + AuthTag]
                SecureRandom.getInstanceStrong().nextBytes(rand);
                fileWrite.write(rand);
            }

            // Total length of keyfile should always be 1+16+32+16+12 = 77 bytes

            // Clear Memory
            s.clearSalt();
            wipeArray(rawKey);
            //wipeArray(password);

            return gk;
        }

        throw new Exception("Failed To Generate");
    }

    protected static SecretKey extractKeyFile(File keyFile, char[] password) throws Exception {

        if (!keyFile.getName().endsWith(".pkk")) { throw new Exception("Unexpected Keyfile Extension");}

        if (keyFile.exists()) {
            FileInputStream fileRead = new FileInputStream(keyFile);

            // Reading key file
            byte version = fileRead.readNBytes(1)[0];
            if (version < VERSION_IDENTIFIER) {throw new Exception("Keyfile Version Old");}
            else if (version > VERSION_IDENTIFIER) {throw new Exception("Keyfile Version Newer");}

            Salt s = new Salt(fileRead.readNBytes(16));         // password salt

            byte[] rawKey;
            if (password != null) { // If password provided then assume the keyfile in encrypted - USER SHOULD KNOW

                rawKey = fileRead.readNBytes(60); // key + auth + iv
                fileRead.close();

                SecretKey dk = deriveKey(password, s);
                byte[] decKey = decryptBytes(dk, rawKey, intToByteArray(VERSION_IDENTIFIER));
                
                if (decKey == null) {throw new Exception("Incorrect Password");}
                SecretKey k = new SecretKeySpec(decKey, ALGORITHM);

                // Clear Memory
                s.clearSalt();
                wipeKey(dk);
                wipeArray(rawKey);
                wipeArray(decKey);

                return k;
            } else {
                rawKey = fileRead.readNBytes(32); // key
                fileRead.close();
                SecretKey k = new SecretKeySpec(rawKey, ALGORITHM);
                wipeArray(rawKey);
                return k;
            }
        }

        throw new Exception("Failed To Extract");
    }

    public static void wipeKey(SecretKey key) {
        if (key != null) {
            try {
                key.destroy();
            } catch (DestroyFailedException e) {
                key = null;
            }
        }
    }


    // ----- Encryption and Decryption methods -----
    protected static byte[] encryptBytes(SecretKey key, byte[] plaintext, byte[] aad) {
        try {
            validateKey(key);

            // Generate IV
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            SecureRandom.getInstanceStrong().nextBytes(iv);

            // Initialize cipher
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);

            // Add Additional Authenticated Data if provided
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }

            // Encrypt
            byte[] ciphertext = cipher.doFinal(plaintext);

            // Combine IV and ciphertext
            byte[] encrypted = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, encrypted, 0, iv.length);
            System.arraycopy(ciphertext, 0, encrypted, iv.length, ciphertext.length);

            // Clear IV from memory
            wipeArray(iv);

            wipeKey(key);
            return encrypted;

        } catch (Exception e) {
            System.out.println(e);
            return null;
        }
    }

    protected static byte[] decryptBytes(SecretKey key, byte[] encrypted, byte[] aad) {
        try {
            validateKey(key);

            if (encrypted.length < GCM_IV_LENGTH_BYTES + (GCM_TAG_LENGTH_BYTES)) {
                throw new IllegalArgumentException("Invalid encrypted data");
            }

            // Extract IV
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            System.arraycopy(encrypted, 0, iv, 0, iv.length);

            // Extract ciphertext
            byte[] ciphertext = new byte[encrypted.length - GCM_IV_LENGTH_BYTES];
            System.arraycopy(encrypted, GCM_IV_LENGTH_BYTES, ciphertext, 0, ciphertext.length);

            // Initialize cipher
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);

            // Add AAD if provided
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }

            // Decrypt
            byte[] plaintext = cipher.doFinal(ciphertext);

            // Clear IV from memory
            wipeArray(iv);
            wipeKey(key);

            return plaintext;

        } catch (Exception e) {
            return null;
        }
    }

    protected static String encryptString(SecretKey key, String plaintext, byte[] aad) {
        byte[] enc = encryptBytes(key, plaintext.getBytes(), aad);
        if (enc != null) {
            return Base64.getEncoder().encodeToString(enc);
        }
        return null;
    }

    protected static String decryptString(SecretKey key, String ciphertext, byte[] aad) {
        byte[] dec = decryptBytes(key, Base64.getDecoder().decode(ciphertext), aad);
        if (dec != null) {
            return new String(dec);
        }
        return null;
    }

    protected static String encryptString(char[] password, String plaintext, byte[] aad) {
        // Encrypt and store provided salt along with the encrypted data
        try {
            Salt s = new Salt();
            SecretKey key = deriveKey(password, s);
            byte[] enc_data = encryptBytes(key, plaintext.getBytes(), aad);
            if (enc_data == null) {
                return null;
            }
            byte[] fin = combineArray(s.getSalt(), enc_data);
            s.clearSalt();
            return Base64.getEncoder().encodeToString(fin);
        } catch (Exception e) {
            return null;
        }
    }

    protected static String decryptString(char[] password, String ciphertext, byte[] aad) {
        try {
            byte[] cipher = Base64.getDecoder().decode(ciphertext);
            Salt s = new Salt(Arrays.copyOfRange(cipher, 0, SALT_LENGTH_BYTES));
            SecretKey key = deriveKey(password, s);
            s.clearSalt();
            byte[] dec = decryptBytes(key, Arrays.copyOfRange(cipher, SALT_LENGTH_BYTES, cipher.length), aad);

            if (dec != null) {
                return new String(dec);
            } else { return null;}

        } catch (Exception e) {
            return null;
        }
    }

    protected static int encryptFile(SecretKey key, char[] password, File inputFile, File outputFile, byte[] aad, boolean useAAD) {
        /*
        Encrypts the passed inputFile and saves cipher text to the outputFile.
        outputFile should contain filename along with the path, and if outputFile already exist then it will be overridden.
        Do note that this method will not delete the inputFile.

        For password encryption keep 'key' null

        returns:
            0: no error
            1: error with exception
         */

        // Sensitive array declaration
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        int  bufferLength;
        if (inputFile.length() < FILE_BUFFER_MAX_SIZE) {
            bufferLength = (int) inputFile.length();
        } else {
            bufferLength = FILE_BUFFER_MAX_SIZE;
        }
        byte[] buffer = new byte[bufferLength];
        byte[] tag = new byte[0];
        byte[] ciphertextChunk = new byte[0];

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            // Generate password salt
            Salt salt = new Salt();

            if (key == null) { // Derive password
                key = deriveKey(password,salt);
            }

            // Generate IV
            SecureRandom.getInstanceStrong().nextBytes(iv);

            // Initialise Cipher
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);

            // Add AAD - byte[] aad can be null if not using
            byte aadUsed = 0;
            if (useAAD) {
                cipher.updateAAD(aad);
                aadUsed = 1;
            }

            // Write metadata
            fos.write(VERSION_IDENTIFIER);                      // 1 byte
            fos.write(aadUsed);                                 // 1 byte
            byte[] filename = encryptBytes(key, inputFile.getName().getBytes(), aad); // encrypted filename
            fos.write(intToByteArray(filename.length));         // 4 bytes
            fos.write(filename);                                // x bytes

            // Write the IV
            fos.write(iv);                                      // 12 bytes

            // Write password salt - if method called from password only, then SALT is used to derive key
            fos.write(salt.getSalt());                             // 16 bytes
            salt.clearSalt();

            if (inputFile.length() != 0) {
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1 && !STOP_FLAG) {
                    ciphertextChunk = cipher.update(buffer, 0, bytesRead);
                    fos.write(ciphertextChunk);
                }

                // Get remaining cipher text and authentication tag
                tag = cipher.doFinal();
                fos.write(tag);
            }

            fos.close();
            fis.close();
        } catch (Exception e) {
            deleteFileSecurely(outputFile);
            return 1;
        }

        // Memory clears
        wipeArray(buffer);
        wipeArray(iv);
        wipeArray(tag);
        wipeArray(ciphertextChunk);
        return 0;
    }

    protected static int decryptFile(SecretKey key, char[] password, File encryptedFile, File outputDirPath, byte[] aad) {
        /*
        Decrypts the passed encryptedFile using a single thread and save to the location outputFilePath, with the original filename.
        Do note that outputFilePath should already exist.

        For password encryption keep 'key' null

        returns:
            0: no error
            1: error with exception
            2: version id old
            3: version id newer
            4: iv length mismatch

         */

        // Sensitive array declaration
        byte[] iv = new byte[0];
        int  bufferLength;
        if (encryptedFile.length() < FILE_BUFFER_MAX_SIZE) {
            bufferLength = (int) encryptedFile.length();
        } else {
            bufferLength = FILE_BUFFER_MAX_SIZE;
        }
        byte[] buffer = new byte[bufferLength];
        byte[] tag = new byte[0];
        byte[] decryptedChunk = new byte[0];

        File outputFile = null;
        try (FileInputStream fis = new FileInputStream(encryptedFile)) {

            // Read metadata
            byte version_id = fis.readNBytes(1)[0];                     // 1 byte
            byte aad_used = fis.readNBytes(1)[0];                       // 1 byte
            if (version_id < VERSION_IDENTIFIER) { return 2;}                // version id old
            else if (version_id > VERSION_IDENTIFIER) { return 3;}           // version id newer
            int filename_length = byteArrayToInt(fis.readNBytes(4));    // 4 bytes
            byte[] encrypted_filename = fis.readNBytes(filename_length);    // x bytes
            iv = fis.readNBytes(GCM_IV_LENGTH_BYTES);                       // 12 byte

            if (iv.length != GCM_IV_LENGTH_BYTES) return 4; // iv length mismatch

            Salt salt = new Salt(fis.readNBytes(16));                   // 16 bytes

            if (key == null) { // password encrypted
                key = deriveKey(password, salt);
            }
            salt.clearSalt();

            // Initialize Cipher
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);

            // Add AAD is used
            if (aad_used == 1) cipher.updateAAD(aad);

            String filename = new String(decryptBytes(key,encrypted_filename,aad));
            outputFile = new File(outputDirPath, filename);
            FileOutputStream fos = new FileOutputStream(outputFile);

            if (encryptedFile.length() > (34+encrypted_filename.length)) { // if original file not empty
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1 && !STOP_FLAG) {
                    decryptedChunk = cipher.update(buffer, 0, bytesRead);
                    if (decryptedChunk != null) {
                        fos.write(decryptedChunk);
                    }
                }

                // Finalize decryption and verify the tag
                tag = cipher.doFinal(); // If tag is invalid, AEADBadTagException is thrown
                fos.write(tag);
            }

            fis.close();
            fos.close();
        } catch (Exception e) {
            deleteFileSecurely(outputFile);
            return 1;
        }

        // Memory clears
        wipeArray(buffer);
        wipeArray(iv);
        wipeArray(tag);
        if (decryptedChunk != null) wipeArray(decryptedChunk);
        return 0;
    }

    protected static boolean deleteFileSecurely(File file) {
        // Deletes file after overriding it with each of the patterns
        if (file == null) return false;

        boolean errorHasOccured = false;

        byte[] patterns = {
                (byte) 0,   //00000000
                (byte) -1,  //11111111
                (byte) -86, //10101010
                (byte) 85,  //01010101
                (byte) 0   //00000000
        };
        long lengthOfFile = file.length();

        for (byte pattern: patterns) {
            try (FileOutputStream fos = new FileOutputStream(file, false)) {
                long bytesWritten = 0;

                int patternLength;
                if (lengthOfFile > 1048576) { //+1mb
                    patternLength = FILE_BUFFER_MAX_SIZE;

                } else if (lengthOfFile > FILE_BUFFER_MAX_SIZE) {
                    patternLength = FILE_BUFFER_MAX_SIZE/2;

                } else {
                    patternLength = (int) lengthOfFile;
                }

                byte[] sequence = new byte[patternLength];
                Arrays.fill(sequence, pattern);

                while (bytesWritten < lengthOfFile) {
                    fos.write(sequence);
                    bytesWritten += patternLength;
                }

                fos.close();
            } catch (Exception e) {
                errorHasOccured = true;
            }
        }

        if (!errorHasOccured) {
            return file.delete();
        }

        return false;
    }

    private static void validateKey(SecretKey key) {
        if (key == null || !key.getAlgorithm().equals(ALGORITHM) ||
                key.getEncoded().length != KEY_SIZE_BITS/8) {
            throw new IllegalArgumentException("Invalid AES-256 key");
        }
    }

    // ----- Salt -----
    protected static final class Salt {
        private final byte[] salt;

        Salt() {
            try {
            salt = new byte[SALT_LENGTH_BYTES];
            SecureRandom.getInstanceStrong().nextBytes(salt);
            } catch (Exception e) {
                throw new SecurityException("Salt generation failed", e);
            }
        }

        private Salt(byte[] s) {
            try {
                this.salt = s;
            } catch (Exception e) {
                throw new SecurityException("Salt saving failed", e);
            }
        }

        private byte[] getSalt() {
            return Arrays.copyOf(salt, salt.length);
        }

        private void clearSalt() {
            wipeArray(salt);
        }

    }

    // ----- Support Methods -----
    protected static byte[] intToByteArray(int value) {
        return new byte[] {
                (byte) (value >> 24), // Get the highest byte
                (byte) (value >> 16), // Get the second byte
                (byte) (value >> 8),  // Get the third byte
                (byte) value          // Get the lowest byte
        };
    }

    protected static int byteArrayToInt(byte[] byteArray) {
        if (byteArray.length != 4) {
            throw new IllegalArgumentException("Byte array must be of length 4");
        }
        return ((byteArray[0] & 0xFF) << 24) |
                ((byteArray[1] & 0xFF) << 16) |
                ((byteArray[2] & 0xFF) << 8) |
                (byteArray[3] & 0xFF);
    }

    protected static byte[] intArrayToByteArray(int[] intArray) {
        byte[] byteArray = new byte[intArray.length * 4];
        for (int i = 0; i < intArray.length; i++) {
            byteArray[i * 4] = (byte) (intArray[i] >> 24);
            byteArray[i * 4 + 1] = (byte) (intArray[i] >> 16);
            byteArray[i * 4 + 2] = (byte) (intArray[i] >> 8);
            byteArray[i * 4 + 3] = (byte) intArray[i];
        }
        return byteArray;
    }

    protected static int[] byteArrayToIntArray(byte[] byteArray) {
        if (byteArray.length % 4 != 0) {
            throw new IllegalArgumentException("Byte array length must be a multiple of 4");
        }
        int[] intArray = new int[byteArray.length / 4];
        for (int i = 0; i < intArray.length; i++) {
            intArray[i] = ((byteArray[i * 4] & 0xFF) << 24) |
                    ((byteArray[i * 4 + 1] & 0xFF) << 16) |
                    ((byteArray[i * 4 + 2] & 0xFF) << 8) |
                    (byteArray[i * 4 + 3] & 0xFF);
        }
        return intArray;
    }

    public static byte[] combineArray(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
    
    protected static void wipeArray(char[] arr) {
        Arrays.fill(arr, '\0');
    }
    protected static void wipeArray(int[] arr) {
        Arrays.fill(arr, 0);
    }
    protected static void wipeArray(byte[] arr) {
        Arrays.fill(arr, (byte) 0);
    }

    protected static int stringToInt(String stringInt) {
        char[] stringIntArr = stringInt.toCharArray();
        int stringIntLength = stringInt.length()-1;
        StringBuilder revStringInt = new StringBuilder();
        char[] revStringIntArr;
        int tempInt = 0;
        int placeValue = 1;
        int output = 0;

        while (stringIntLength >= 0) {
            revStringInt.append(stringIntArr[stringIntLength]);
            stringIntLength--;
        }

        revStringIntArr = revStringInt.toString().toCharArray();

        for (char echar : revStringIntArr) {
            switch (echar) {
                case ' ', '0' -> tempInt = 0;
                case '1' -> tempInt = 1;
                case '2' -> tempInt = 2;
                case '3' -> tempInt = 3;
                case '4' -> tempInt = 4;
                case '5' -> tempInt = 5;
                case '6' -> tempInt = 6;
                case '7' -> tempInt = 7;
                case '8' -> tempInt = 8;
                case '9' -> tempInt = 9;
            }
            output += tempInt*placeValue;
            placeValue = placeValue*10;
        }
        return output;
    }

    protected static int charToInt(char charInt) {
        int output = 0 ;
        switch (charInt) {
            case '1' -> output = 1;
            case '2' -> output = 2;
            case '3' -> output = 3;
            case '4' -> output = 4;
            case '5' -> output = 5;
            case '6' -> output = 6;
            case '7' -> output = 7;
            case '8' -> output = 8;
            case '9' -> output = 9;
        }

        return output;
    }

    protected static String generateRandomString(int length) {
        String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        Random random = new Random();
        StringBuilder sb = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            int randomIndex = random.nextInt(CHARACTERS.length());
            char randomChar = CHARACTERS.charAt(randomIndex);
            sb.append(randomChar);
        }

        return sb.toString();
    }

}