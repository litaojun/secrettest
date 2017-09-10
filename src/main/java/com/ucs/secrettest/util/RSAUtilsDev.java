package com.ucs.secrettest.util;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import sun.misc.BASE64Decoder;



/**
 * @author Administrator
 *
 */
public class RSAUtilsDev {

	
	/**
     * 加密算法RSA
     */
	public static final String KEY_ALGORITHM_RSA = "RSA";
	
    
    /**
     * 生成RSA 密钥对
     * @return
     */
    public static KeyPair generateRSAKeyPair() {
        try {
            Security.addProvider(new BouncyCastleProvider());
            SecureRandom random = new SecureRandom();
            KeyPairGenerator generator = KeyPairGenerator.getInstance(KEY_ALGORITHM_RSA);
            generator.initialize(2048, random);
            KeyPair a =generator.generateKeyPair();
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    public static void writeKey(String path, Key key) throws Exception {
        FileOutputStream fos = new FileOutputStream(path);
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(key);
        oos.close();
    }
    public static Key readKey(String path) throws Exception {
        FileInputStream fis = new FileInputStream(path);
        ObjectInputStream bis = new ObjectInputStream(fis);
        Object object = bis.readObject();
        bis.close();
        return (Key) object;
    }
    /**
     * <P>
     * 私钥解密
     * </p>
     * 
     * @param encryptedData 已加密数据
     * @param privateKey 私钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] encryptedData, byte[] privateKeyEncode)
            throws Exception {
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKeyEncode);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM_RSA);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateK);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return decryptedData;
    }
    
    /**
     * 私钥解密 base64字符串
     * @param base64EncryptedData 
     * @param privateKeyEncode
     * @return
     * @throws Exception
     */
    public static byte[] decryptBase64ByPrivateKey(String base64EncryptedData, byte[] privateKeyEncode)
            throws Exception {
        return decryptByPrivateKey(EncryptUtilDev.base64Decrypt(base64EncryptedData), privateKeyEncode);
    }

    /**
     * <p>
     * 公钥解密 字符串
     * </p>
     * 
     * @param encryptedData 已加密数据
     * @param publicKey 公钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] encryptedData, byte[] publicKeyEncode)
            throws Exception {
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKeyEncode);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM_RSA);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicK);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return decryptedData;
    }
    
    /**
     * 公钥解密 base64
     * 
     * @param base64EncryptedData
     * @param publicKeyEncode
     * @return
     * @throws Exception
     */
    public static byte[] decryptBase64ByPublicKey(String base64EncryptedData, byte[] publicKeyEncode)
            throws Exception {
        return decryptByPublicKey(EncryptUtilDev.base64Decrypt(base64EncryptedData),publicKeyEncode);
    }

    /**
     * <p>
     * 公钥加密
     * </p>
     * 
     * @param data 源数据
     * @param publicKey 公钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(String data, byte[] publicKeyEncode )
            throws Exception {
    	data = StringUtil.NVL(data);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKeyEncode);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM_RSA);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicK);
        
        byte[] encryptedData = cipher.doFinal(data.getBytes("utf-8"));
        return encryptedData;
    }

    /**
     * <p>
     * 私钥加密
     * </p>
     * 
     * @param data 源数据
     * @param privateKey 私钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(String data, byte[] privateKeyEncode)
            throws Exception {
    	data = StringUtil.NVL(data);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKeyEncode);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM_RSA);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateK);
        
        byte[] encryptedData = cipher.doFinal(data.getBytes("utf-8"));
        return encryptedData;
    }

    /**
     * <p>
     * 获取私钥
     * </p>
     * 
     * @param KeyPair 密钥对
     * @return
     * @throws Exception
     */
    public static String getPrivateKey(KeyPair kepair)
            throws Exception {
        return  EncryptUtilDev.base64Encrypt(kepair.getPrivate().getEncoded());
    }
    

    /**
     * <p>
     * 获取公钥
     * </p>
     * 
     * @param KeyPair 密钥对
     * @return
     * @throws Exception
     */
    public static String getPublicKey(KeyPair kepair)
            throws Exception {
        return  EncryptUtilDev.base64Encrypt(kepair.getPublic().getEncoded());
    }

    /** 
     * 从字符串中加载公钥 
     * @param publicKeyStr 公钥数据字符串 
     * @throws Exception 加载公钥时产生的异常 
     */  
    public static RSAPublicKey loadPublicKey(String publicKeyStr) throws Exception{  
        try {  
            BASE64Decoder base64Decoder= new BASE64Decoder();  
            byte[] buffer= base64Decoder.decodeBuffer(publicKeyStr);  
            KeyFactory keyFactory= KeyFactory.getInstance("RSA");  
            X509EncodedKeySpec keySpec= new X509EncodedKeySpec(buffer);  
            RSAPublicKey publicKey= (RSAPublicKey) keyFactory.generatePublic(keySpec);  
            return publicKey;
        } catch (NoSuchAlgorithmException e) {  
            throw new Exception("无此算法");  
        } catch (InvalidKeySpecException e) {  
            throw new Exception("公钥非法");  
        } catch (IOException e) {  
            throw new Exception("公钥数据内容读取错误");  
        } catch (NullPointerException e) {  
            throw new Exception("公钥数据为空");  
        }  
    }
    public static RSAPrivateKey loadPrivateKey(String privateKeyStr) throws Exception{  
        try {  
            BASE64Decoder base64Decoder= new BASE64Decoder();  
            byte[] buffer= base64Decoder.decodeBuffer(privateKeyStr);  
            PKCS8EncodedKeySpec keySpec= new PKCS8EncodedKeySpec(buffer);  
            KeyFactory keyFactory= KeyFactory.getInstance("RSA");  
            RSAPrivateKey privateKey= (RSAPrivateKey) keyFactory.generatePrivate(keySpec);  
            return privateKey;
        } catch (NoSuchAlgorithmException e) {  
            throw new Exception("无此算法");  
        } catch (InvalidKeySpecException e) {  
            throw new Exception("私钥非法");  
        } catch (IOException e) {  
            throw new Exception("私钥数据内容读取错误");  
        } catch (NullPointerException e) {  
            throw new Exception("私钥数据为空");  
        }  
    }  
    public static void main(String[] args) throws Exception
    {
    	KeyPair kp = generateRSAKeyPair() ;
    	writeKey("d://litaojun/pri.key",kp.getPrivate());
    	writeKey("d://litaojun/pub.key",kp.getPublic());
    }
}
