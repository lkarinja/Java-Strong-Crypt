/*
Copyright © 2015-2017 Leejae Karinja

This file is part of Java StrongCrypt.

Java StrongCrypt is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Java StrongCrypt is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Java StrongCrypt.  If not, see <http://www.gnu.org/licenses/>.
*/
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;

public class FileCrypt {

    /**
     * Encrypts a byte array with AES. Asks for a destination file name for the
     * encrypted data, and a password for the AES key.
     * 
     * @param data Byte array of data to encrypt
     * @return Returns void on completion
     */
    protected static void encrypt(byte[] data) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String encryptedFileName = "";
            String password = "";

            System.out.print("Destination of Encrypted File Name (Leave Blank for Default): ");
            encryptedFileName += reader.readLine();
            if (encryptedFileName.equals(""))
                encryptedFileName = "Encrypted.bin";

            System.out.print("Password: ");
            password += reader.readLine();

            File encryptFile = new File("Encrypted.bin");
            InputStream dataStream = new ByteArrayInputStream(data);
            OutputStream encryptedOut = new FileOutputStream(encryptFile);

            AES.encrypt(128, password.toCharArray(), dataStream, encryptedOut);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return;
    }

    /**
     * Decrypts a binary file with AES. Asks for a file name for the encrypted
     * data, a file destination for the decrypted data, and a password for the
     * AES key.
     * 
     * @return Returns void on completion
     */
    protected static void decyrpt() {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String encryptedFileName = "";
            String decryptedFileName = "";
            String password = "";

            System.out.print("Encrypted File Name (Leave Blank for Default): ");
            encryptedFileName += reader.readLine();
            if (encryptedFileName.equals(""))
                encryptedFileName = "Encrypted.bin";

            System.out.print("Destination of Decrypted File Name (Leave Blank for Default): ");
            decryptedFileName += reader.readLine();
            if (decryptedFileName.equals(""))
                decryptedFileName = "Decrypted.bin";

            System.out.print("Password: ");
            password += reader.readLine();

            File encryptFile = new File(encryptedFileName);
            File decryptFile = new File(decryptedFileName);
            InputStream encryptedIn = new FileInputStream(encryptFile);
            OutputStream decryptedOut = new FileOutputStream(decryptFile);

            AES.decrypt(password.toCharArray(), encryptedIn, decryptedOut);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return;
    }

}
