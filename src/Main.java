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
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Inet4Address;
import java.security.MessageDigest;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

public class Main {

	public static void main(String[] args) {
		try {
			/*
			 * BufferedReader reader = new BufferedReader(new
			 * InputStreamReader(System.in)); String input = reader.readLine();
			 * final String[] inputCommands = input.split(" ");
			 * if(inputCommands[0].equalsIgnoreCase("run")){
			 * if(inputCommands[1].equalsIgnoreCase("server")){
			 * if(Integer.parseInt(inputCommands[2]) > 0 &&
			 * Integer.parseInt(inputCommands[2]) < 65536){ Thread b = new
			 * Thread(){ public void run(){ Server s = new
			 * Server(Integer.parseInt(inputCommands[2])); s.start(); return; }
			 * }; b.start(); }else{
			 * System.err.println("Usage: \"run server [port]\""); } }else
			 * if(inputCommands[1].equalsIgnoreCase("client")){
			 * if(Integer.parseInt(inputCommands[2]) > 0 &&
			 * Integer.parseInt(inputCommands[2]) < 65536){ Thread a = new
			 * Thread(){ public void run(){ try{ File encryptFile = new
			 * File(inputCommands[3]); InputStream dataStream = new
			 * FileInputStream(encryptFile); byte[] data = new byte[(int)
			 * encryptFile.length()]; dataStream.read(data); dataStream.close();
			 * Client c = new
			 * Client(Inet4Address.getLocalHost().getHostAddress(),
			 * Integer.parseInt(inputCommands[2]), data); c.start(); }catch
			 * (Exception e){ e.printStackTrace(); } return; } }; a.start();
			 * }else{ System.err.println("Usage: \"run client [port] [file]\"");
			 * } }else{
			 * System.err.println("Usage: \"run [\'client\'|\'server\']\""); }
			 * }else if(inputCommands[0].equalsIgnoreCase("decrypt")){
			 * FileCrypt.decyrpt(); }else{
			 * System.err.println("Usage: \"[run|decrypt]\""); }
			 */
			Thread b = new Thread() {

				public void run() {
					Server s = new Server(3474);
					s.start();
					return;
				}

			};
			b.start();
			Thread a = new Thread() {

				public void run() {
					try {
						byte[] data = { (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1 };
						Main.printData(toIntArray(data), "Sending: ");
						Client c = new Client(Inet4Address.getLocalHost().getHostAddress(), 3474, data);
						c.start();
					} catch (Exception e) {
						e.printStackTrace();
					}
					return;
				}

			};
			a.start();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return;
	}

	public static void printData(int[] data, String prompt) { // DEBUG
		int x = 0;
		String dataAsString = "";
		for (x = 0; x < data.length; x++) {
			dataAsString += /* (char) */data[x];
		}
		System.out.println(prompt + dataAsString);
		return;
	}

	public static int[] toIntArray(byte[] data) {
		int x = 0;
		int[] intData = new int[data.length];
		for (x = 0; x < data.length; x++) {
			intData[x] = (int) data[x];
		}
		return intData;
	}

	public static byte[] toByteArray(int[] data) {
		int x = 0;
		byte[] byteData = new byte[data.length];
		for (x = 0; x < data.length; x++) {
			byteData[x] = (byte) (data[x] % 256);
		}
		return byteData;
	}

	public static String hash(String base) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(base.getBytes("UTF-8"));
			StringBuffer hexString = new StringBuffer();

			for (int i = 0; i < hash.length; i++) {
				String hex = Integer.toHexString(0xff & hash[i]);
				if (hex.length() == 1) hexString.append('0');
				hexString.append(hex);
			}

			return hexString.toString();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "";
	}

	public static void printSocketInfo(SSLSocket s) { // DEBUG
		System.out.println("Socket class: " + s.getClass());
		System.out.println("_Remote address = " + s.getInetAddress().toString());
		System.out.println("_Remote port = " + s.getPort());
		System.out.println("_Local socket address = " + s.getLocalSocketAddress().toString());
		System.out.println("_Local address = " + s.getLocalAddress().toString());
		System.out.println("_Local port = " + s.getLocalPort());
		System.out.println("_Need client authentication = " + s.getNeedClientAuth());
		SSLSession ss = s.getSession();
		System.out.println("_Cipher suite = " + ss.getCipherSuite());
		System.out.println("_Protocol = " + ss.getProtocol());
		return;
	}

	public static void printServerSocketInfo(SSLServerSocket s) { // DEBUG
		System.out.println("Server socket class: " + s.getClass());
		System.out.println("_Socket address = " + s.getInetAddress().toString());
		System.out.println("_Socket port = " + s.getLocalPort());
		System.out.println("_Need client authentication = " + s.getNeedClientAuth());
		System.out.println("_Want client authentication = " + s.getWantClientAuth());
		System.out.println("_Use client mode = " + s.getUseClientMode());
		return;
	}
	
	public static void log(String s){
		System.out.println(s);
		return;
	}
	
	public static void log(int s){
		System.out.println(s);
		return;
	}
	
	public static void log(long s){
		System.out.println(s);
		return;
	}
	
	public static void log(double s){
		System.out.println(s);
		return;
	}
	
	public static void log(float s){
		System.out.println(s);
		return;
	}

	public static byte[] serialize(Object obj) {
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			ObjectOutputStream os = new ObjectOutputStream(out);
			os.writeObject(obj);
			return out.toByteArray();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static Object deserialize(byte[] data) {
		try {
			ByteArrayInputStream in = new ByteArrayInputStream(data);
			ObjectInputStream is = new ObjectInputStream(in);
			return is.readObject();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

}
