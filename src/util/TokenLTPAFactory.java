/*
 * The MIT License (MIT)
 * 
 * Copyright (c) 2014 samir.araujo@gmail.com
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package util;

import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * Utility class witch handles LTPA Tokens 
 */
public class TokenLTPAFactory {

	// Base64 encoder & decoder
	private final BASE64Decoder decoder = new BASE64Decoder( );
	private final BASE64Encoder encoder = new BASE64Encoder( );
	
	private String sharedKey;
	private String keyPassword;
	private String privateKey;	
	
	/**
	 * LTPA Versions
	 */
	public enum LTPA_VERSION {
		LTPA,
		LTPA2
	}
	
	/**
	 * Types of cripting algorithms
	 */
	private enum CRIPTING_ALGORITHM {
		AES_DECRIPTING_ALGORITHM( "AES/CBC/PKCS5Padding" ),
		DES_DECRIPTING_ALGORITHM( "DESede/ECB/PKCS5Padding" );
		
		private final String text;
		
		private CRIPTING_ALGORITHM( String text ) {
			this.text = text;
		}
		

		@Override
		public String toString( ) {
			return this.text;
		}
	};
	
	/**
	 * LTPA Token Factory constructor
	 * Give as parameter a filename of a Properties file containing the following
	 * attributes
	 * com.ibm.websphere.ltpa.KeyPassword
	 * com.ibm.websphere.ltpa.PrivateKey
	 * com.ibm.websphere.ltpa.PublicKey
	 * com.ibm.websphere.ltpa.3DESKey
	 * 
	 * @param propertiesFileName
	 * @throws Exception  
	 */
	public TokenLTPAFactory( String propertiesFileName ) throws Exception {
		Properties prop = new Properties();
		prop.load( new FileInputStream( new File( propertiesFileName )));
		this.keyPassword = prop.getProperty( "com.ibm.websphere.ltpa.KeyPassword" );
		this.privateKey = prop.getProperty( "com.ibm.websphere.ltpa.PrivateKey" );
		this.sharedKey = prop.getProperty( "com.ibm.websphere.ltpa.3DESKey" );
		if ( this.keyPassword == null ) {
			throw new Exception( "Invalid Key Password" );
		}		
	}

    /**
     * Prepare an initialization vector for the cryptografic algorithm
     * @param key of the crypt algorithm
     * @param size of the vector
     * @return 
     */
    private IvParameterSpec generateIvParameterSpec(byte key[], int size) {
    	byte[] row = new byte[size];
        for (int i = 0; i < size; i++) {
            row[i] = key[i];
        } // for        
        return new IvParameterSpec(row);
    }	

	/**
	 * Helper function which do the hard work of encrypting and decrypting
	 * 
	 * @param target data to be [en/de]crypted
	 * @param key DES key
	 * @param algorithm Algorithm used during the crypting process
	 * @param mode 1 for decrypting and 2 for encrypting
	 * @return dados [en/de]crypted data
	 * @throws Exception
	 */
	private byte[] crypt(byte[] target, byte[] key, CRIPTING_ALGORITHM algorithm, int mode ) throws Exception {
        SecretKey sKey = null;

        if (algorithm.name().indexOf("AES") != -1) {
            sKey = new SecretKeySpec(key, 0, 16, "AES");
        } else {
            DESedeKeySpec kSpec = new DESedeKeySpec(key);
            SecretKeyFactory kFact = SecretKeyFactory.getInstance("DESede" );
            sKey = kFact.generateSecret(kSpec);
        } // else
        Cipher cipher = Cipher.getInstance(algorithm.text);

        if (algorithm.name().indexOf("ECB") == -1) {
            if (algorithm.name( ).indexOf("AES") != -1) {
                IvParameterSpec ivs16 = generateIvParameterSpec(key, 16);
                cipher.init(mode, sKey, ivs16);
            } else {
                cipher.init(mode, sKey);
            } // else
        } else {
            cipher.init(mode, sKey);
        } // else
        return cipher.doFinal(target);		
	}    
	    
	/**
	 * Decrypt a given encoded key, using a DES algorithm
	 * @param key
	 * @param keyPassword
	 * @return
	 * @throws Exception
	 */
	private byte[] getSecretKey(String key, String keyPassword) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA");
		md.update(keyPassword.getBytes());
		byte[] hash3DES = new byte[24];
		System.arraycopy(md.digest(), 0, hash3DES, 0, 20);
		Arrays.fill(hash3DES, 20, 24, (byte) 0);
		final Cipher cipher = Cipher.getInstance(CRIPTING_ALGORITHM.DES_DECRIPTING_ALGORITHM.text );
		final KeySpec keySpec = new DESedeKeySpec(hash3DES);
		final Key secretKey = SecretKeyFactory.getInstance("DESede").generateSecret(keySpec);
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] secret = cipher.doFinal(decoder.decodeBuffer(key));
		return secret;
	}
	
    /**
     * Compute the final structure of the RSA rawKey
     * @param rawKey
     */
    private void setRSAKey(byte rawKey[][]) {
        BigInteger abiginteger[] = new BigInteger[8];
        for(int i = 0; i < 8; i++) {
            if(rawKey[i] != null) {
                abiginteger[i] = new BigInteger(1, rawKey[i]);
            } // if
        } // for

        if(abiginteger[3].compareTo(abiginteger[4]) < 0) {
            BigInteger biginteger = abiginteger[3];
            abiginteger[3] = abiginteger[4];
            abiginteger[4] = biginteger;
            biginteger = abiginteger[5];
            abiginteger[5] = abiginteger[6];
            abiginteger[6] = biginteger;
            abiginteger[7] = null;
        } // if
        
        if(abiginteger[7] == null)
            abiginteger[7] = abiginteger[4].modInverse(abiginteger[3]);        
        if(abiginteger[0] == null)
            abiginteger[0] = abiginteger[3].multiply(abiginteger[4]);
        if(abiginteger[1] == null)
            abiginteger[1] = abiginteger[2].modInverse(abiginteger[3].subtract(BigInteger.valueOf(1L)).multiply(abiginteger[4].subtract(BigInteger.valueOf(1L))));
        if(abiginteger[5] == null)
            abiginteger[5] = abiginteger[1].remainder(abiginteger[3].subtract(BigInteger.valueOf(1L)));
        if(abiginteger[6] == null)
            abiginteger[6] = abiginteger[1].remainder(abiginteger[4].subtract(BigInteger.valueOf(1L)));
        
        for(int j = 0; j < 8; j++) {
            rawKey[j] = abiginteger[j].toByteArray();
        } // for
    }	

    /**
     * ISO Padding algorithm for RSA
     * @param data
     * @param k
     * @return
     */
    private byte[] padISO9796(byte data[], int k ) {
        byte padded[] = null;
        k--;
        if(data.length * 16 > k + 3) {
            return null;
        } // if
        padded = new byte[(k + 7) / 8];
        for(int l = 0; l < padded.length / 2; l++) {
            padded[padded.length - 1 - 2 * l] = data[data.length - 1 - l % data.length];
        } // for
        if((padded.length & 1) != 0) {
            padded[0] = data[data.length - 1 - (padded.length / 2) % data.length];
        } // if
        long l1 = 0x1ca76bd0f249853eL;
        for(int i1 = 0; i1 < padded.length / 2; i1++) {
            int k1 = padded.length - 1 - 2 * i1;
            padded[k1 - 1] = (byte)(int)((l1 >> (padded[k1] >>> 2 & 0x3c) & 15L) << 4 | l1 >> ((padded[k1] & 0xf) << 2) & 15L);
        } // for
        padded[padded.length - 2 * data.length] ^= 1;
        int j1 = k % 8;
        padded[0] &= (byte)((1 << j1) - 1);
        padded[0] |= 1 << ((j1 - 1) + 8) % 8;
        padded[padded.length - 1] = (byte)(padded[padded.length - 1] << 4 | 6);
        return padded;
    }

    /**
     * Basic RSA encrypting algorithm
     * @param rawKey
     * @param data
     * @return
     */
    private byte[] rsa( byte[][] rawKey, byte[] data ) {
        byte encoded[] = null;
        int rawKeyLength = rawKey.length;
        BigInteger abiginteger[] = new BigInteger[rawKeyLength];
        int l;
        int k1;
        if(rawKeyLength == 8) {
            l = 3;
            k1 = rawKeyLength;
            abiginteger[0] = new BigInteger(rawKey[0]);
        } else {
            l = 0;
            k1 = 2;
        } // else
        
        do {
            abiginteger[l] = new BigInteger(rawKey[l]);
        } while(++l < k1);
        
        int l2 = l != 2 ? abiginteger[3].bitLength() + abiginteger[4].bitLength() : abiginteger[0].bitLength();
        int j2 = (l2 + 7) / 8;
        BigInteger biginteger;
        byte abyte4[];
        if((abyte4 = padISO9796(data, l2)) == null) {
            return null;
        } // if
        biginteger = new BigInteger(1, abyte4);

        if(rawKeyLength > 3) {
            BigInteger biginteger1 = biginteger.remainder(abiginteger[3]).modPow(abiginteger[5], abiginteger[3]);
            BigInteger biginteger2 = biginteger.remainder(abiginteger[4]).modPow(abiginteger[6], abiginteger[4]);
            biginteger = biginteger1.add(abiginteger[3]).subtract(biginteger2).multiply(abiginteger[7]).remainder(abiginteger[3]).multiply(abiginteger[4]).add(biginteger2);
        } else {
            biginteger = biginteger.modPow(abiginteger[1], abiginteger[0]);
        } // else
        
        if( biginteger.multiply(BigInteger.valueOf(2L)).compareTo(abiginteger[0]) == 1) {
            biginteger = abiginteger[0].subtract(biginteger);
        } // if
        
        byte abyte5[] = biginteger.toByteArray();
        rawKeyLength = 0;
        l = abyte5.length;
        k1 = j2;
        if( l - k1 == 0 ) {
            return abyte5;
        } // if
        if(l < 0) {
            rawKeyLength = -l;
            l = 0;
        } // if
        encoded = new byte[k1];
        System.arraycopy(abyte5, l, encoded, rawKeyLength, k1 - rawKeyLength);
        return encoded;
    }
    
	/**
	 * Decode a LTPA v1 or v2 token
	 * @param tokenLTPA
	 * @param version
	 * @return
	 * @throws Exception
	 */
	public UserMetadata decodeLTPAToken( String tokenLTPA, LTPA_VERSION version ) throws Exception {
		// lets get the shared key
		byte[] sharedKey = getSecretKey(this.sharedKey, this.keyPassword);
		// and decode from base64 to bytes the given token 
		byte[] encryptedBytes = decoder.decodeBuffer(tokenLTPA);
		// to get the plain decrypted token after applying the decrypting algorithm
		String plainToken = new String( crypt(encryptedBytes, sharedKey, version.equals( LTPA_VERSION.LTPA2 ) ?				
			CRIPTING_ALGORITHM.AES_DECRIPTING_ALGORITHM : CRIPTING_ALGORITHM.DES_DECRIPTING_ALGORITHM, Cipher.DECRYPT_MODE ) );		
		// finally, lets parse the decrypted token into the user metadata
		System.out.println("PlainToken="+plainToken);
		return new UserMetadata( plainToken, version );
	}
	
	/**
	 * Encode a given usermetadata object into a LTPA Token v1 or v2
	 * @param userData
	 * @param version
	 * @return
	 * @throws Exception
	 */
	public String encodeLTPAToken( UserMetadata userData, LTPA_VERSION version ) throws Exception {		
		// lets start by recovering the private key, which is encrypted
		LTPAPrivateKey ltpaPrivKey = new LTPAPrivateKey( getSecretKey( this.privateKey, this.keyPassword ) );
		byte[][] rawKey = ltpaPrivKey.getRawKey();
		setRSAKey( rawKey );

		// new lets prepare to prepare the signature
		MessageDigest md1JCE = MessageDigest.getInstance("SHA" );
		byte[] plainUserDataBytes = md1JCE.digest(userData.getPlainUserMetadata().getBytes() );
		
		// lets sign the hash created previously with the private key
		byte [] encodedSignatureBytes = null;
		if ( version.equals( LTPA_VERSION.LTPA2 ) ) {
	        BigInteger biginteger = new BigInteger( rawKey[0] );
	        BigInteger biginteger1 = new BigInteger( rawKey[2] );
	        BigInteger biginteger2 = new BigInteger( rawKey[3] );
	        BigInteger biginteger3 = new BigInteger( rawKey[4] );
	        BigInteger biginteger4 = biginteger1.modInverse(biginteger2.subtract(BigInteger.ONE).multiply(biginteger3.subtract(BigInteger.ONE)));
	        KeyFactory keyfactory = KeyFactory.getInstance("RSA" );
	        
	        RSAPrivateKeySpec rsaprivatekeyspec = new RSAPrivateKeySpec(biginteger, biginteger4);
	        PrivateKey privatekey = keyfactory.generatePrivate(rsaprivatekeyspec);
	        Signature signer = Signature.getInstance("SHA1withRSA" );
	        signer.initSign(privatekey);
			signer.update( plainUserDataBytes, 0, plainUserDataBytes.length );
			
			// signing the hash
			encodedSignatureBytes = signer.sign( );			
		} else {
			// signing the hash
			encodedSignatureBytes = rsa( rawKey, plainUserDataBytes );
		} // else
		
		// ok. lets encode the signature with Base64
		String base64Signature = encoder.encodeBuffer( encodedSignatureBytes ).replaceAll( "[\r\n]", "");
		
		// now, lets create the plain text version of the token
		StringBuffer token = new StringBuffer( );
		token.append( userData.getPlainUserMetadata( ) ).append( "%" );
		token.append( userData.getExpire( ) ).append( "%" );
		token.append( base64Signature );
		
		// finally lets crypt everything with the private key and then 
		// to apply a base64 encoding 
		byte[] tokenBytes = token.toString().getBytes("UTF8" );
		byte[] encryptedBytes = crypt(tokenBytes, getSecretKey( sharedKey, keyPassword), version.equals( LTPA_VERSION.LTPA2 ) ?  
			CRIPTING_ALGORITHM.AES_DECRIPTING_ALGORITHM : CRIPTING_ALGORITHM.DES_DECRIPTING_ALGORITHM , Cipher.ENCRYPT_MODE );
		return encoder.encodeBuffer(encryptedBytes).replaceAll( "[\r\n]", "");
	}
	
	public static void main( String[] args ) throws Exception {
		/*
		try {
			// Bypass Unlimited Strength Cryptography Restrictions
			Field field = Class.forName("javax.crypto.JceSecurity").
			getDeclaredField("isRestricted");
			field.setAccessible(true);
			field.set(null, java.lang.Boolean.FALSE);
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());
		}
		*/
		
		if ( args.length != 2 ) {
			System.out.println("Usage: " + TokenLTPAFactory.class.getName() + " <-d1|-d2|-e1|-e2> <token>" );
			System.out.println( " Where: -d<1|2>=decode -e<1|2>=encode <1=LTPA 1 and 2=LTPA 2>");
			System.exit(0);
		} // if
			TokenLTPAFactory factory = new TokenLTPAFactory( "C:\\Users\\vbc00297.CH2K\\workspace\\WASLTPA\\src\\keys.was85.properties" );		
			TokenLTPAFactory.LTPA_VERSION ltpaVersion = args[0].contains( "1" ) ? 
					TokenLTPAFactory.LTPA_VERSION.LTPA : TokenLTPAFactory.LTPA_VERSION.LTPA2;
		String token;
		
		if ( args[0].matches( "\\-d[12]" ) ) {			
			token = factory.decodeLTPAToken( args[1], ltpaVersion ).toString( );			
		} else {			
			token = factory.encodeLTPAToken( new UserMetadata( args[1], ltpaVersion ), ltpaVersion );			
		} // else
		System.out.println("javascript:document.cookie="+'"'+"LtpaToken2="+token+'"' );
	}
}
