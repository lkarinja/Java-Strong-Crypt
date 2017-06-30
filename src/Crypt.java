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

public class Crypt implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 6676258080165881408L;
	private OneTimePad pad = new OneTimePad();

	/**
	 * Default constructor
	 */
	Crypt() {

	}

	/**
	 * Encrypts an integer array with a two way one time pad
	 * 
	 * @param data Integer array of data to encrypt
	 * @return Returns encrypted data
	 */
	protected int[] cryptStart(int[] data) {
		int[] crypt = new int[data.length];
		pad.setData(data);
		if (!pad.hasKey()) pad.genKey();
		crypt = pad.encrypt();
		return crypt;
	}

	/**
	 * Decrypts an integer array with a two way one time pad
	 * 
	 * @param data Integer array of data to decrypt
	 * @return Returns decrypted data
	 */
	protected int[] cryptFinish(int[] data) {
		int[] crypt = new int[data.length];
		pad.setData(data);
		if (!pad.hasKey()) pad.genKey();
		crypt = pad.decrypt();
		return crypt;
	}

}
