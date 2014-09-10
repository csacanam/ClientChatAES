package control;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;


public class Cliente {
	
	//Dirección IP del servidor
	static InetAddress localhost = null;
	//Puerto del servidor
	static int puertoHilo = 0;
	//DatagramPacket para enviar y recibir paquetes
	static DatagramPacket dPacketRecibe, dPacketEnvio;
	//DatagramSocket
	static DatagramSocket dSocketCliente;

	public static void main(String[] args) 
	{
		try 
		{
			localhost = InetAddress.getLocalHost();
		} catch (UnknownHostException e1) 
		{
			System.out.println("Error obteniendo la direccion localhost");
		}

		try 
		{
			// Enviando info al servidor para conectarse
			dSocketCliente = new DatagramSocket();
			byte[] envio = new byte[250];
			dPacketEnvio = new DatagramPacket(envio, envio.length, localhost, 4000);
			dSocketCliente.send(dPacketEnvio);
			// Recibiendo respuesta para guardar parámetros del servidor
			byte[] buzon = new byte[250];
			dPacketRecibe = new DatagramPacket(buzon, buzon.length);
			dSocketCliente.receive(dPacketRecibe);
			puertoHilo = dPacketRecibe.getPort();

			// Generar clave secreta
			SecretKey secretKey = diffieHellman();
			

			//Leer cada mensaje, cifrarlo y enviarlo al servidor
			Scanner in = new Scanner(System.in);
			while (true)
			{
				System.out.println("Escribe tu mensaje");
				String mensaje = in.nextLine();
				String mensajeCifrado = AES.symmetricEncrypt(mensaje, secretKey);
				byte[] mensajeCifradoDatos = mensajeCifrado.getBytes();
				dPacketEnvio = new DatagramPacket(mensajeCifradoDatos, mensajeCifradoDatos.length, localhost, puertoHilo);
				dSocketCliente.send(dPacketEnvio);
			}

		} catch (SocketException e) 
		{
			System.out.println("Error creando el socket");
		} catch (IOException e) 
		{
			System.out.println("Error en el flujo de informacion");
		}

	}

	/**
	 * Permite generar una clave secreta usando el algoritmo de Diffie Hellman
	 * @return SecretKey clave secreta generada por el algoritmo Diffie Hellman
	 */
	public static SecretKey diffieHellman() 
	{
		SecretKey aesSecretKey = null;
		try 
		{
			String algorithm = "DH";

			System.out.println("Calculando los parámetros Diffie-Hellman...");
			
			AlgorithmParameterGenerator pGenerator = AlgorithmParameterGenerator.getInstance(algorithm);
			pGenerator.init(1024);
			
			AlgorithmParameters pars = pGenerator.generateParameters();
			
			DHParameterSpec dhPSpec = (DHParameterSpec)pars.getParameterSpec(DHParameterSpec.class);
			
			//Crear un generador de par de claves local, basado en los parametros DH
			KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(algorithm);
			keyGenerator.initialize(dhPSpec);
			
			//Par de claves
			KeyPair keyPair = keyGenerator.generateKeyPair();
			
			//Crear KeyAgreement local
			KeyAgreement keyAgreement = KeyAgreement.getInstance(algorithm);
			keyAgreement.init(keyPair.getPrivate());
			
			//Obtener los bytes de la clave publica, para enviarlos al servidor
			byte [] pubKeyBuffer = keyPair.getPublic().getEncoded();
			System.out.println("Enviando bytes de la clave publica...");
			dPacketEnvio = new DatagramPacket(pubKeyBuffer, pubKeyBuffer.length, localhost, puertoHilo);
			dSocketCliente.send(dPacketEnvio);
			System.out.println("Cantidad de bytes enviados: " + pubKeyBuffer.length);
			
			//Esperar por los bytes clave del servidor
			System.out.println("Recibiendo los bytes de la clave publica del servidor");
			
			// Recibiendo respuesta
			byte[] buzon = new byte[512];
			dPacketRecibe = new DatagramPacket(buzon, buzon.length);
			dSocketCliente.receive(dPacketRecibe);
			puertoHilo = dPacketRecibe.getPort();
			System.out.println("Cantidad de bytes recibidos: " + buzon.length);
			
			KeyFactory kf = KeyFactory.getInstance(algorithm);
			X509EncodedKeySpec x509ks = new X509EncodedKeySpec(buzon);
			PublicKey remotePubKey = kf.generatePublic(x509ks);
			
			//Generar la clave secreta
			keyAgreement.doPhase(remotePubKey, true);
			aesSecretKey = keyAgreement.generateSecret("AES");
			
			//Imprimir la clave secreta
			byte [] theKey = aesSecretKey.getEncoded();
			System.out.println("Clave secreta: " + bytesToHex(theKey));

		} catch (NoSuchAlgorithmException e) 
		{
			System.out.println("El algoritmo no existe");
		} catch (InvalidParameterSpecException e) 
		{
			System.out.println("Parámetros invalidos");
		} catch (InvalidAlgorithmParameterException e) 
		{
			System.out.println("Algoritmo invalido");
		} catch (InvalidKeyException e) 
		{
			System.out.println("Clave invalida");
		} catch (IOException e) 
		{
			System.out.println("Error en el flujo");
		} catch (InvalidKeySpecException e)
		{
			System.out.println("Especificacion de clave invalida");
		}
		
		return aesSecretKey;
	}


	/**
	 * Permite pasar de bytes a hexadecimal
	 * 
	 * @param data
	 *            Informacion representada en bytes
	 * @return Representacion en hexadecimal de la informacion en bytes
	 */
	public static String bytesToHex(byte[] data) 
	{
		if (data == null) 
		{
			return null;
		} else 
		{
			int len = data.length;
			String str = "";
			for (int i = 0; i < len; i++) 
			{
				if ((data[i] & 0xFF) < 16)
					str = str + "0" + java.lang.Integer.toHexString(data[i] & 0xFF);
				else
					str = str + java.lang.Integer.toHexString(data[i] & 0xFF);
			}
			return str.toUpperCase();
		}
	}

}
