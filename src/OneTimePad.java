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
import java.io.Serializable;
import java.security.SecureRandom;

public class OneTimePad implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = 1044576996199320761L;
    private int[] data;
    private int[] key;
    private boolean hasKey;

    /**
     * Default constructor
     */
    OneTimePad() {

    }

    /**
     * Constructor with specified data to pad
     * 
     * @param data Integer array of data to pad
     */
    OneTimePad(int[] data) {
        this.data = data;
        // Main.printData(data, "Data Set To: "); //DEBUG
    }

    /**
     * Sets the data to pad
     * 
     * @param data Integer array of data to pad
     * @return Returns void on completion
     */
    protected void setData(int[] data) {
        this.data = data;
        // Main.printData(data, "Data Set To: "); //DEBUG
        return;
    }

    /**
     * Generates an integer array key of equal length to the data filled with
     * secure random numbers
     * 
     * @return Returns void on completion
     */
    protected void genKey() {
        int x = 0;
        SecureRandom rand = new SecureRandom();
        this.key = new int[this.data.length];
        for (x = 0; x < this.key.length; x++) {
            int temp = rand.nextInt();
            this.key[x] = ((temp % 256) < 0) ? ((temp % 256) + 256) : (temp % 256);
        }
        this.hasKey = true;
        // Main.printData(this.key, "Key Generated: "); //DEBUG
        return;
    }

    /**
     * Decides whether the key has been created or not
     * 
     * @return Returns true if key is created, false if key is not created
     */
    protected boolean hasKey() {
        return this.hasKey;
    }

    /**
     * Encrypts the set data with the pad
     * 
     * @return Returns an integer array of the encrypted padded data
     */
    protected int[] encrypt() {
        int x = 0;
        int[] crypted = new int[key.length];
        for (x = 0; x < this.key.length; x++) {
            crypted[x] = (this.data[x] + this.key[x]) % 256;
        }
        // Main.printData(crypted, "Encrypted To: "); //DEBUG
        return crypted;
    }

    /**
     * Decrypts the set data with the pad
     * 
     * @return Returns an integer array of the decrypted padded data
     */
    protected int[] decrypt() {
        int x = 0;
        int[] crypted = new int[key.length];
        for (x = 0; x < this.key.length; x++) {
            crypted[x] = ((this.data[x] - this.key[x]) < 0) ? ((this.data[x] - this.key[x]) + 256) : (this.data[x] - this.key[x]);
        }
        // Main.printData(crypted, "Decrypted To: "); //DEBUG
        return crypted;
    }

}
