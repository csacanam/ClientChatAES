package control;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Base64;


/**
 * Clase AES donde se encuentran los métodos para encriptar y desencriptar
 * 
 *Se tenía un problema que decía que no se podía encriptar o desencriptar si la entrada
 *no era múltiplo de 16 bytes. La solución se encontró acá: 
 *http://stackoverflow.com/questions/17567996/illegal-block-size-exception-input-length-must-be-multiple-of-16-when-decrypting
 *
 *Se usó la librería de Codes de Apache para codificar y de codificar cadenas con base a 64 bytes.
 *Esta última se encuentra disponible en: http://commons.apache.org/proper/commons-codec/download_codec.cgi
 * @author csacanam
 */

public class AES 
{
	
	private AES()
	{
		
	}

	/**
	 * Permite encriptar un mensaje con una clave secreta
	 * @param text Mensaje que va a ser encriptado
	 * @param key Clave secreta con la cual se va a encriptar el mensaje
	 * @return String Mensaje encriptado
	 */
	public static String symmetricEncrypt(String text, SecretKey key) 
	{
		String encryptedString = null;
		byte[] encryptText = text.getBytes();
		Cipher cipher;
		try 
		{
			cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			encryptedString = Base64.encodeBase64String(cipher.doFinal(encryptText));
		} catch (Exception e) 
		{
			System.out.println("Error encriptando");
		}
		return encryptedString;
	}

	/**
	 * Permite desencriptar una mensaje con una clave secreta
	 * @param text Mensaje encriptado
	 * @param key Clave secreta con la cual se va a desencriptar
	 * @return String Mensaje desencriptado
	 */
	public static String symmetricDecrypt(String text, SecretKey key) 
	{
		Cipher cipher;
		String encryptedString = null;
		byte[] encryptText = null;
		try 
		{
			encryptText = Base64.decodeBase64(text);
			cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, key);
			encryptedString = new String(cipher.doFinal(encryptText));
		} catch (Exception e) 
		{
			System.out.println("Error desencriptando");
		}
		return encryptedString;
	}

}
