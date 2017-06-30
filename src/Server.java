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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class Server {

	private int port;
	private byte[] nonce;
	private byte[] keyData;
	private SSLSocket client;
	private SSLServerSocket server;
	private DataOutputStream writer;
	private DataInputStream reader;

	/**
	 * Default constructor
	 */
	Server() {

	}

	/**
	 * Constructor with specified port
	 * 
	 * @param port Port to start the server on
	 */
	Server(int port) {
		this.port = port;
	}

	/**
	 * Generates a one time use secure random number to be used as the password
	 * for a keystore
	 * 
	 * @return Returns void on completion
	 */
	protected void genNonce() {
		SecureRandom rand = new SecureRandom();
		this.nonce = new byte[2048];
		rand.nextBytes(nonce);
		return;
	}

	/**
	 * Generates a one time use keystore for use with an SSL session
	 * 
	 * @return Returns void on completion
	 */
	protected void genKeystore() {
		try {
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(null, (new String(this.nonce)).toCharArray());
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			ks.store(os, (new String(this.nonce)).toCharArray());
			this.keyData = os.toByteArray();
			os.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return;
	}

	/**
	 * Sets the port for the server to start on
	 * 
	 * @param port Port to start the server on
	 * @return Returns void on completion
	 */
	protected void setPort(int port) {
		this.port = port;
		return;
	}

	/**
	 * Starts the one time padded SSL session
	 * 
	 * @return Returns void on completion
	 */
	protected void start() {
		try {
			// System.out.println("Starting Server on "+ java.net.Inet4Address.getLocalHost().getHostAddress() + ":" + this.port); // DEBUG
			int[] data;
			Crypt crypterA = new Crypt();
			Crypt crypterB = new Crypt();
			Crypt crypterC = new Crypt();

			if (this.nonce == null) this.genNonce();
			if (this.keyData == null) this.genKeystore();

			this.startConnection();

			//Receive length of data to receive
			data = new int[this.receiveData()[0]];
			Main.log("Length of Data to Receive: " + data.length);
			
			crypterA.cryptStart(new int[data.length]);
			crypterC.cryptStart(new int[data.length]);
			
			//Receive Client crypterA and set it to crypterB
			crypterB = (Crypt) Main.deserialize(Main.toByteArray(this.receiveData()));
			Main.printData(Main.toIntArray((Main.serialize(crypterB))), "Server crypterB: "); // DEBUG
			Main.log("Server crypterB hash: " + Main.hash(new String(Main.serialize(crypterB))));

			//Send Server crypterA to Client
			this.sendData(Main.toIntArray(Main.serialize(crypterA)));
			
			//Send Server crypterB encrypted with Server crypterA
			//this.sendData(crypterA.cryptStart(Main.toIntArray(Main.serialize(crypterB))));
			
			/*
			 * byte[] dataFinal = new byte[data.length]; int x = 0; for (x = 0;
			 * x < dataFinal.length; x++) { dataFinal[x] = (byte) data[x]; }
			 * FileCrypt.encrypt(dataFinal);
			 */

		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			this.endConnection();
		}
		return;
	}

	/**
	 * Creates an SSL session
	 * 
	 * @return Returns void on completion
	 */
	private void startConnection() {
		try {
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(new ByteArrayInputStream(this.keyData), (new String(this.nonce).toCharArray()));

			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			kmf.init(ks, (new String(this.nonce).toCharArray()));

			SSLContext context = SSLContext.getInstance("TLS");
			context.init(kmf.getKeyManagers(), null, null);

			SSLServerSocketFactory ssf = context.getServerSocketFactory();

			this.server = (SSLServerSocket) ssf.createServerSocket(this.port);
			this.server.setEnabledCipherSuites(this.server.getSupportedCipherSuites());
			this.server.setEnabledProtocols(this.server.getSupportedProtocols());

			// Main.printServerSocketInfo(this.server); //DEBUG

			this.client = (SSLSocket) this.server.accept();
			this.client.startHandshake();

			this.writer = new DataOutputStream(this.client.getOutputStream());
			this.reader = new DataInputStream(this.client.getInputStream());

			// Main.printSocketInfo(this.client); //DEBUG
		} catch (Exception e) {
			e.printStackTrace();
		}
		return;
	}

	/**
	 * Ends the SSL session
	 * 
	 * @return Returns void on completion
	 */
	private void endConnection() {
		try {
			this.writer.close();
			this.reader.close();
			this.server.close();
			this.client.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return;
	}

	/**
	 * Sends data to the client
	 * 
	 * @param data Data to send to the client
	 * @return Returns void on completion
	 */
	protected void sendData(int[] data) {
		try {
			int x = 0;
			for (x = 0; x < data.length; x++) {
				this.writer.writeInt(data[x]);
			}
			this.writer.writeInt(-1);
			this.writer.flush();
			//Main.printData(data, "Server Sent: "); // DEBUG
		} catch (Exception e) {
			e.printStackTrace();
		}
		return;
	}

	/**
	 * Receives data from the client
	 * 
	 * @return Returns data received from the client
	 */
	protected int[] receiveData() {
		try {
			List<Integer> dataRead = new ArrayList<Integer>();
			int temp = this.reader.readInt();
			while (temp != (-1)) {
				dataRead.add(temp);
				temp = this.reader.readInt();
			}
			Integer[] data = new Integer[dataRead.size()];
			data = dataRead.toArray(data);
			int[] dataFinal = new int[data.length];
			int x = 0;
			for (x = 0; x < data.length; x++) {
				dataFinal[x] = data[x].intValue();
			}
			// Main.printData(dataFinal, "Server Received: "); //DEBUG
			return dataFinal;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

}
