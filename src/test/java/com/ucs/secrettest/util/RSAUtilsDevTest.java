package com.ucs.secrettest.util;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.Test;

public class RSAUtilsDevTest 
{
	    String path="D:\\aws\\key\\";
	    String data="i am china men;";
       // @Test
        public void generateRSAKeyPairTest() throws Exception
        {
        	KeyPair keypair = RSAUtilsDev.generateRSAKeyPair();
        	PrivateKey ppk = keypair.getPrivate();
        	PublicKey pbk = keypair.getPublic();
        	byte[] b = ppk.getEncoded();
        	byte[] c=pbk.getEncoded();
        	String prikeystr = EncryptUtilDev.base64Encrypt(b);
        	String pubkeystr = EncryptUtilDev.base64Encrypt(c);
            System.out.println(String.format("prikeystr=%s,pubkeystr=%s", new String[]{prikeystr,pubkeystr}));
        	
        	RSAUtilsDev.writeKey(path+"ppk.key", ppk);
        	RSAUtilsDev.writeKey(path+"pbk.key", pbk);
        	RSAUtilsDev.storeToPem(ppk, path+"ppk.pem");
        	RSAUtilsDev.storeToPem(pbk, path+"pbk.pem");
        }
        
        //@Test
        public void encryptByPrivateKeyTest()
        {
        	
        }
        
        @Test
        public void encryptByPublicKeyTest() throws Exception
        {
        	PublicKey puky = RSAUtilsDev.getPemPublic(path+"ppk.pem");
        	PrivateKey prk = RSAUtilsDev.getPemPrivate(path+"ppk.pem");
        	byte[] secritedata = RSAUtilsDev.encryptByPublicKey(data, puky.getEncoded());
        	byte[] curdata = RSAUtilsDev.decryptByPrivateKey(secritedata, prk.getEncoded());
        	String a = new String(curdata,"UTF-8");
        	System.out.println(a);
        }
        
}
