package com.ucs.secrettest.util;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;


@SuppressWarnings("restriction")
public class EncryptUtilDev {
	
	/**
     * 加密算法MD5
     */
    public static final String ALGORITHM_MD5 = "MD5";
    
    
    /**
     * 加密算法SHA-256
     */
    public static final String ALGORITHM_SHA_256 = "SHA-256";
    
    
    /**
     * 加密算法SHA-512
     */
    public static final String ALGORITHM_SHA_512 = "SHA-512";
    
    
    /**
     * 加密算法des
     */
    public static final String ALGORITHM_DES = "DESede/ECB/PKCS5Padding";
    
    
    public static final String KEY_ALGORITHM_DES =  "DESede";
    
	
	/**
     * MD5 摘要计算(byte[]).
     *
     * @param src byte[]
     * @throws java.lang.Exception
     * @return byte[] 16 bit digest
     */
	public static String md5Encrypt(String strSrc) {
		MessageDigest md = null;
		String strDes = null;

		byte[] bt = strSrc.getBytes();
		try {
			md = MessageDigest.getInstance(ALGORITHM_MD5);
			md.update(bt);
			strDes = bytes2Hex(md.digest()); //to HexString
		} catch (NoSuchAlgorithmException e) {
			return null;
		}
		return strDes;
	}

	
	/**
	 * 数组转化16进制字符串
	 * @param bts
	 * @return
	 */
	public static String bytes2Hex(byte[] bts) {
		String des = "";
		String tmp = null;
		for (int i = 0; i < bts.length; i++) {
			tmp = (Integer.toHexString(bts[i] & 0xFF));
			if (tmp.length() == 1) {
				des += "0";
			}
			des += tmp;
		}
		return des;
	}
	
	public static String base64Encrypt(byte[] bts){
		return new BASE64Encoder().encode(bts);
	}
	
	public static byte[] base64Decrypt(String base64Str) throws IOException{
		return new BASE64Decoder().decodeBuffer(base64Str);
	}

    
    /**
     * 3des加密
     * @param secretKey
     * @param data
     * @return
     * @throws Exception
     */
    public static String tripleDesEncrypt(String secretKey, String data) throws Exception {
    	if(data == null) return "";
    	byte[] encode = tripleDesEncrypt(secretKey, data.getBytes("utf8"));
    	return base64Encrypt(encode);
    }
    
	/**
	 * 3des 加密
	 * @param byteKey
	 * @param data
	 * @return
	 * @throws Exception 
	 */
    public static byte[] tripleDesEncrypt(String secretKey, byte[] data) throws Exception {
    	try {
			Cipher cipher = Cipher.getInstance(ALGORITHM_DES);
			cipher.init(Cipher.ENCRYPT_MODE, genTripleDesKey(secretKey));
			byte[] encode = cipher.doFinal(data);
			return encode;
		} catch (Exception e) {
			throw new Exception("3des 解密失败",e);
		}
    }
    
    
    
    /**
	 * 3des 解密
	 * @param key
	 * @param data
	 * @return
	 * @throws Exception 
	 */
	public static byte[] tripleDesDecrypt(String secKey, byte[] data) throws Exception {
		try {
			Cipher cipher = Cipher.getInstance(ALGORITHM_DES);
			cipher.init(Cipher.DECRYPT_MODE, genTripleDesKey(secKey));
			byte[] decode =cipher.doFinal(data);
			return decode;
		} catch (Exception e) {
			throw new Exception("3des 解密失败",e);
		}
	}
	
	/**
	 * 3des 解密
	 * @param secKey
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static String tripleDesDecrypt(String secKey, String data) throws Exception {
		if(data == null) return "";
		return new String(tripleDesDecrypt(secKey,(base64Decrypt(data))),"utf8");
	}
    
    
	
	
	
	
    
    
    /**
     * 特殊检验算法
     * @param src
     * @return
     */
    @SuppressWarnings("unused")
	private static String getCheckData(String src)
    {
        byte[] byteArray=src.getBytes();
        int j=byteArray.length/8+1;
        byte[] macArray=new byte[8];
        for(int i=0;i<macArray.length;i++)
            macArray[i]=(byte)("0".charAt(0));
        byte[] dataValue=new byte[j*8];
        for(int i=0;i<dataValue.length;i++)
            dataValue[i]=(byte)("0".charAt(0));
        System.arraycopy(byteArray,0,dataValue,0,byteArray.length);
        for(int i=0;i<j;i++)
        {
            byte[] tempValue=new byte[8];
            for(int m=0;m<8;m++)
            {
                tempValue[m]=dataValue[i*8+m];
            }
            getXorValue(macArray,tempValue);
        }
        return bytes2Hex(macArray);
    }
    
    private static void getXorValue(byte[] macArray,byte[] tempValue)
    {
        int i;
		for ( i = 0; i < 8; i ++ ) 		
		    macArray[i] ^= tempValue[i];
    }
    
    /**
     * 左加补零算法
     * @param str
     * @param length
     * @return
     */
    @SuppressWarnings("unused")
	private static  String AddLeft0(String str,int length)
    {
        if (str==null)
            str="";
        boolean haveSign=false;
        if (!str.equalsIgnoreCase("") && str.substring(0,1).equals("-"))
        {
            length=length-1;
            str=str.substring(1);
            haveSign=true;
        }
        str=str.trim();
        while (str.length()<length)
    		str="0"+str;
        if (haveSign)
            str="-"+str;
        return str;
    }
    
	
    
	
    /**
     * 生成3DES密钥.
     * @param strKey
     * @return
     * @throws Exception 
     */
    public static SecretKey genTripleDesKey(String strKey) throws Exception {
    	if (strKey == null) {
    		return null;
    	}
    	byte[] keys = new byte[24];
    	byte[] srcArr = strKey.getBytes("utf8");
		if(srcArr.length >= 24)
			System.arraycopy(srcArr,0,keys,0, 24);
		else{
			//补满24字节，右补0
			System.arraycopy(srcArr,0,keys,0, srcArr.length);
		}
    	return new SecretKeySpec(keys, KEY_ALGORITHM_DES );
    }
    
    
    /** 
     * 传入文本内容，返回 SHA-256 串 
     *  
     * @param strText 
     * @return 
     */  
    public static String SHA256(final String strText)  
    {  
      return SHA(strText, "SHA-256");  
    }  
    
    /** 
     * 传入文本内容，返回 SHA-512 串 
     *  
     * @param strText 
     * @return 
     */  
    public static String SHA512(final String strText)  
    {  
      return SHA(strText, "SHA-512");  
    }  
    
    
    /** 
     * 字符串 SHA 加密 
     *  
     * @param strSourceText 
     * @return 
     */  
    private static String SHA(final String strText, final String strType)  
    {  
    
      // 是否是有效字符串  
      if (strText != null && strText.length() > 0)  
      {  
        try  
        {  
          // SHA 加密开始  
          // 创建加密对象 并傳入加密类型  
          MessageDigest messageDigest = MessageDigest.getInstance(strType);  
          // 传入要加密的字符串  
          messageDigest.update(strText.getBytes());  
          // 得到 byte 类型结果  
          byte[] byteBuffer = messageDigest.digest();  
    
          return bytes2Hex(byteBuffer);
        }  
        catch (NoSuchAlgorithmException e)  
        {  
          e.printStackTrace();  
        }  
      }  
    
      return null;  
    }  
}
