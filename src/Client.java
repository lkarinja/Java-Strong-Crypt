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

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class Client {

	private int[] dataToSend;
	private String host;
	private int port;
	private byte[] nonce;
	private byte[] keyData;
	private SSLSocket server;
	private DataOutputStream writer;
	private DataInputStream reader;

	/**
	 * Default constructor
	 */
	Client() {

	}

	/**
	 * Constructor with specified host and port
	 * 
	 * @param host Host to connect to
	 * @param port Port to connect to
	 */
	Client(String host, int port) {
		this.host = host;
		this.port = port;
	}

	/**
	 * Constructor with specified host, port, and data to send
	 * 
	 * @param host Host to connect to
	 * @param port Port to connect to
	 * @param data Data to send
	 */
	Client(String host, int port, byte[] data) {
		this.host = host;
		this.port = port;
		this.dataToSend = new int[data.length];
		int x = 0;
		for (x = 0; x < data.length; x++) {
			this.dataToSend[x] = (int) data[x];
		}
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
	 * Sets the host to connect to
	 * 
	 * @param host Host to connect to
	 * @return Returns void on completion
	 */
	protected void setHost(String host) {
		this.host = host;
		return;
	}

	/**
	 * Sets the port to connect to
	 * 
	 * @param port Port to connect to
	 * @return Returns void on completion
	 */
	protected void setPort(int port) {
		this.port = port;
		return;
	}

	/**
	 * Sets the data to send
	 * 
	 * @param data Data to send
	 * @return Returns void on completion
	 */
	protected void setData(byte[] data) {
		int x = 0;
		this.dataToSend = new int[data.length];
		for (x = 0; x < data.length; x++) {
			this.dataToSend[x] = (int) data[x];
		}
		return;
	}

	/**
	 * Starts the one time padded SSL session
	 * 
	 * @return Returns void on completion
	 */
	protected void start() {
		try {
			// System.out.println("Starting Client Connection to " + this.host +
			// ":" + this.port); //DEBUG
			int[] data = new int[this.dataToSend.length];
			Crypt crypterA = new Crypt();
			Crypt crypterB = new Crypt();
			Crypt crypterC = new Crypt();

			int x = 0;
			for (x = 0; x < this.dataToSend.length; x++) {
				data[x] = (int) this.dataToSend[x];
			}

			if (this.nonce == null) this.genNonce();
			if (this.keyData == null) this.genKeystore();

			this.startConnection();
			
			//Send the length of the data to send
			this.sendData(new int[]{(int) data.length});
			Main.log("Length of Data to Send: " + data.length);
			
			crypterA.cryptStart(new int[data.length]);
			crypterC.cryptStart(new int[data.length]);
			
			//Send Client crypterA to Server
			this.sendData(Main.toIntArray(Main.serialize(crypterA)));
			
			//Receive Server crypterA and set it to crypterB
			crypterB = (Crypt) Main.deserialize(Main.toByteArray(this.receiveData()));
			Main.printData(Main.toIntArray((Main.serialize(crypterB))), "Client crypterB: "); // DEBUG
			Main.log("Client crypterB hash: " + Main.hash(new String(Main.serialize(crypterB))));
			
			
			
			//this.sendData(data);
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

			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(ks);

			SSLContext context = SSLContext.getInstance("TLS");
			context.init(null, tmf.getTrustManagers(), null);

			SSLSocketFactory sf = context.getSocketFactory();

			this.server = (SSLSocket) sf.createSocket(this.host, this.port);
			this.server.setEnabledCipherSuites(this.server.getSupportedCipherSuites());
			this.server.setEnabledProtocols(this.server.getSupportedProtocols());
			this.server.startHandshake();

			this.writer = new DataOutputStream(this.server.getOutputStream());
			this.reader = new DataInputStream(this.server.getInputStream());

			// Main.printSocketInfo(this.server); //DEBUG
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
		} catch (Exception e) {
			e.printStackTrace();
		}
		return;
	}

	/**
	 * Sends data to the server
	 * 
	 * @param data Data to send to the server
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
			//Main.printData(data, "Client Sent: "); // DEBUG
		} catch (Exception e) {
			e.printStackTrace();
		}
		return;
	}

	/**
	 * Receives data from the server
	 * 
	 * @return Returns data received from the server
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
			// Main.printData(dataFinal, "Client Received: "); //DEBUG
			return dataFinal;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

}
