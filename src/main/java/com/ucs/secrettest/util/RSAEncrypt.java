package com.ucs.secrettest.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import sun.misc.BASE64Decoder;

public class RSAEncrypt {
	
	private static  String DEFAULT_PUBLIC_KEY
//		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQChDzcjw/rWgFwnxunbKp7/4e8w" + "\r" +
//		"/UmXx2jk6qEEn69t6N2R1i/LmcyDT1xr/T2AHGOiXNQ5V8W4iCaaeNawi7aJaRht" + "\r" +
//		"Vx1uOH/2U378fscEESEG8XDqll0GCfB1/TjKI2aitVSzXOtRs8kYgGU78f7VmDNg" + "\r" +
//		"XIlk3gdhnzh+uoEQywIDAQAB" + "\r";
	   ="MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0t+s/VzXC0NeaX1pQy+W"+"\r"+
 			"0MfVpiiDXeGXerIqD5YFjg1siCBF+qTW9WLbRmKp3Evdm+JQNRIK1emh6a5xKOIi"+"\r"+
 			"+Uyf7F9BjSaY5QRQqhT9o1CRdeiaOP8uvLC8BwKZKETps43FZrDjiQ7+NjkUyDEk"+"\r"+
 			"F3LyjSFnsWC/ANuziTNSb20I/UUwoK3W6Ghff8Kx6pWc7IF4xEk5TEDB/jOk9D/G"+"\r"+
 			"Puqzw5B4PiK4a0dkdwxUKy4mFtgowF/5rDPWF2f3gOvqEifARn7pqEp3ANuY8tNQ"+"\r"+
 			"KyH/OwMcf8NROafjMF0yGuZ/OLrsVobN4NAzgMnoHivvKLDgP+yfuRj2lP3JyhCP"+"\r"+
 			"gwIDAQAB"+"\r";
	//private static  String DEFAULT_PRIVATE_KEY
//		"MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKEPNyPD+taAXCfG" + "\r" +
//		"6dsqnv/h7zD9SZfHaOTqoQSfr23o3ZHWL8uZzINPXGv9PYAcY6Jc1DlXxbiIJpp4" + "\r" +
//		"1rCLtolpGG1XHW44f/ZTfvx+xwQRIQbxcOqWXQYJ8HX9OMojZqK1VLNc61GzyRiA" + "\r" +
//		"ZTvx/tWYM2BciWTeB2GfOH66gRDLAgMBAAECgYBp4qTvoJKynuT3SbDJY/XwaEtm" + "\r" +
//		"u768SF9P0GlXrtwYuDWjAVue0VhBI9WxMWZTaVafkcP8hxX4QZqPh84td0zjcq3j" + "\r" +
//		"DLOegAFJkIorGzq5FyK7ydBoU1TLjFV459c8dTZMTu+LgsOTD11/V/Jr4NJxIudo" + "\r" +
//		"MBQ3c4cHmOoYv4uzkQJBANR+7Fc3e6oZgqTOesqPSPqljbsdF9E4x4eDFuOecCkJ" + "\r" +
//		"DvVLOOoAzvtHfAiUp+H3fk4hXRpALiNBEHiIdhIuX2UCQQDCCHiPHFd4gC58yyCM" + "\r" +
//		"6Leqkmoa+6YpfRb3oxykLBXcWx7DtbX+ayKy5OQmnkEG+MW8XB8wAdiUl0/tb6cQ" + "\r" +
//		"FaRvAkBhvP94Hk0DMDinFVHlWYJ3xy4pongSA8vCyMj+aSGtvjzjFnZXK4gIjBjA" + "\r" +
//		"2Z9ekDfIOBBawqp2DLdGuX2VXz8BAkByMuIh+KBSv76cnEDwLhfLQJlKgEnvqTvX" + "\r" +
//		"TB0TUw8avlaBAXW34/5sI+NUB1hmbgyTK/T/IFcEPXpBWLGO+e3pAkAGWLpnH0Zh" + "\r" +
//		"Fae7oAqkMAd3xCNY6ec180tAe57hZ6kS+SYLKwb4gGzYaCxc22vMtYksXHtUeamo" + "\r" +
//		"1NMLzI2ZfUoX" + "\r" ;
	private static  String DEFAULT_PRIVATE_KEY ="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"+"\r"+
 			"OAk="+"\r";
	/**
	 * 私钥
	 */
	private RSAPrivateKey privateKey;

	/**
	 * 公钥
	 */
	private RSAPublicKey publicKey;
	
	/**
	 * 字节数据转字符串专用集合
	 */
	private static final char[] HEX_CHAR= {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	

	/**
	 * 获取私钥
	 * @return 当前的私钥对象
	 */
	public RSAPrivateKey getPrivateKey() {
		return privateKey;
	}

	/**
	 * 获取公钥
	 * @return 当前的公钥对象
	 */
	public RSAPublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * 随机生成密钥对
	 */
	public void genKeyPair(){
		KeyPairGenerator keyPairGen= null;
		try {
			keyPairGen= KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		keyPairGen.initialize(1024, new SecureRandom());
		KeyPair keyPair= keyPairGen.generateKeyPair();
		this.privateKey= (RSAPrivateKey) keyPair.getPrivate();
		this.publicKey= (RSAPublicKey) keyPair.getPublic();
	}

	/**
	 * 从文件中输入流中加载公钥
	 * @param in 公钥输入流
	 * @throws Exception 加载公钥时产生的异常
	 */
	public void loadPublicKey(InputStream in) throws Exception{
		try {
			BufferedReader br= new BufferedReader(new InputStreamReader(in));
			String readLine= null;
			StringBuilder sb= new StringBuilder();
			while((readLine= br.readLine())!=null){
				if(readLine.charAt(0)=='-'){
					continue;
				}else{
					sb.append(readLine);
					sb.append('\r');
				}
			}
			loadPublicKey(sb.toString());
		} catch (IOException e) {
			throw new Exception("公钥数据流读取错误");
		} catch (NullPointerException e) {
			throw new Exception("公钥输入流为空");
		}
	}


	/**
	 * 从字符串中加载公钥
	 * @param publicKeyStr 公钥数据字符串
	 * @throws Exception 加载公钥时产生的异常
	 */
	public void loadPublicKey(String publicKeyStr) throws Exception{
		try {
			BASE64Decoder base64Decoder= new BASE64Decoder();
			byte[] buffer= base64Decoder.decodeBuffer(publicKeyStr);
			KeyFactory keyFactory= KeyFactory.getInstance("RSA");
			X509EncodedKeySpec keySpec= new X509EncodedKeySpec(buffer);
			this.publicKey= (RSAPublicKey) keyFactory.generatePublic(keySpec);
		} catch (NoSuchAlgorithmException e) {
			throw new Exception("无此算法");
		} catch (InvalidKeySpecException e) {
			System.out.println(e.getMessage());
			throw new Exception("公钥非法");
		} catch (IOException e) {
			throw new Exception("公钥数据内容读取错误");
		} catch (NullPointerException e) {
			throw new Exception("公钥数据为空");
		}
	}

	/**
	 * 从文件中加载私钥
	 * @param keyFileName 私钥文件名
	 * @return 是否成功
	 * @throws Exception 
	 */
	public void loadPrivateKey(InputStream in) throws Exception{
		try {
			BufferedReader br= new BufferedReader(new InputStreamReader(in));
			String readLine= null;
			StringBuilder sb= new StringBuilder();
			while((readLine= br.readLine())!=null){
				if(readLine.charAt(0)=='-'){
					continue;
				}else{
					sb.append(readLine);
					sb.append('\r');
				}
			}
			loadPrivateKey(sb.toString());
		} catch (IOException e) {
			throw new Exception("私钥数据读取错误");
		} catch (NullPointerException e) {
			throw new Exception("私钥输入流为空");
		}
	}

	public void loadPrivateKey(String privateKeyStr) throws Exception{
		try {
			BASE64Decoder base64Decoder= new BASE64Decoder();
			byte[] buffer= base64Decoder.decodeBuffer(privateKeyStr);
			PKCS8EncodedKeySpec keySpec= new PKCS8EncodedKeySpec(buffer);
			KeyFactory keyFactory= KeyFactory.getInstance("RSA");
			this.privateKey= (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
		} catch (NoSuchAlgorithmException e) {
			throw new Exception("无此算法");
		} catch (InvalidKeySpecException e) {
			throw new Exception("私钥非法");
		} catch (IOException e) {
			throw new Exception("私钥数据内容读取错误");
		} catch (NullPointerException e) {
			System.out.println(e.getMessage());
			throw new Exception("私钥数据为空");
		}
	}

	/**
	 * 加密过程
	 * @param publicKey 公钥
	 * @param plainTextData 明文数据
	 * @return
	 * @throws Exception 加密过程中的异常信息
	 */
	public byte[] encrypt(RSAPublicKey publicKey, byte[] plainTextData) throws Exception{
		if(publicKey== null){
			throw new Exception("加密公钥为空, 请设置");
		}
		Cipher cipher= null;
		try {
			cipher= Cipher.getInstance("RSA", new BouncyCastleProvider());
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] output= cipher.doFinal(plainTextData);
			return output;
		} catch (NoSuchAlgorithmException e) {
			throw new Exception("无此加密算法");
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
			return null;
		}catch (InvalidKeyException e) {
			throw new Exception("加密公钥非法,请检查");
		} catch (IllegalBlockSizeException e) {
			throw new Exception("明文长度非法");
		} catch (BadPaddingException e) {
			throw new Exception("明文数据已损坏");
		}
	}

	/**
	 * 解密过程
	 * @param privateKey 私钥
	 * @param cipherData 密文数据
	 * @return 明文
	 * @throws Exception 解密过程中的异常信息
	 */
	public byte[] decrypt(RSAPrivateKey privateKey, byte[] cipherData) throws Exception{
		if (privateKey== null){
			throw new Exception("解密私钥为空, 请设置");
		}
		Cipher cipher= null;
		try {
			cipher= Cipher.getInstance("RSA", new BouncyCastleProvider());
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] output= cipher.doFinal(cipherData);
			return output;
		} catch (NoSuchAlgorithmException e) {
			throw new Exception("无此解密算法");
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
			return null;
		}catch (InvalidKeyException e) {
			throw new Exception("解密私钥非法,请检查");
		} catch (IllegalBlockSizeException e) {
			throw new Exception("密文长度非法");
		} catch (BadPaddingException e) {
			throw new Exception("密文数据已损坏");
		}		
	}

	
	/**
	 * 字节数据转十六进制字符串
	 * @param data 输入数据
	 * @return 十六进制内容
	 */
	public static String byteArrayToString(byte[] data){
		StringBuilder stringBuilder= new StringBuilder();
		for (int i=0; i<data.length; i++){
			//取出字节的高四位 作为索引得到相应的十六进制标识符 注意无符号右移
			stringBuilder.append(HEX_CHAR[(data[i] & 0xf0)>>> 4]);
			//取出字节的低四位 作为索引得到相应的十六进制标识符
			stringBuilder.append(HEX_CHAR[(data[i] & 0x0f)]);
			if (i<data.length-1){
				stringBuilder.append(' ');
			}
		}
		return stringBuilder.toString();
	}


	public static void main(String[] args){
		RSAEncrypt rsaEncrypt= new RSAEncrypt();
		//rsaEncrypt.genKeyPair();

		//加载公钥
		try {
			rsaEncrypt.loadPublicKey(RSAEncrypt.DEFAULT_PUBLIC_KEY);
			System.out.println("加载公钥成功");
		} catch (Exception e) {
			System.err.println(e.getMessage());
			System.err.println("加载公钥失败");
		}

		//加载私钥
		try {
			rsaEncrypt.loadPrivateKey(RSAEncrypt.DEFAULT_PRIVATE_KEY);
			System.out.println("加载私钥成功");
		} catch (Exception e) {
			System.err.println(e.getMessage());
			System.err.println("加载私钥失败");
		}

		//测试字符串
		String encryptStr= "Test String chaijunkun";

		try {
			//加密
			byte[] cipher = rsaEncrypt.encrypt(rsaEncrypt.getPublicKey(), encryptStr.getBytes());
			//解密
			byte[] plainText = rsaEncrypt.decrypt(rsaEncrypt.getPrivateKey(), cipher);
			System.out.println("密文长度:"+ cipher.length);
			System.out.println(RSAEncrypt.byteArrayToString(cipher));
			System.out.println("明文长度:"+ plainText.length);
			System.out.println(RSAEncrypt.byteArrayToString(plainText));
			System.out.println(new String(plainText));
		} catch (Exception e) {
			System.err.println(e.getMessage());
		}
	}
}