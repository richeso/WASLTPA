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

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * User Metadata, used to build the LTPA Token
 */
public class UserMetadata {
	private long expire = 0l;
	// u
	private String user = null;
	private String host = null;
	private int port = 0;
	// java.naming.provider.url
	private String namingProvider = null;
	// process.serverName
	private String serverName = null;
	// security.authMechOID
	private String authenticationMethod = null;
	private String type = null;
	private byte[] signature = null;	
	private TokenLTPAFactory.LTPA_VERSION ltpaVersion = TokenLTPAFactory.LTPA_VERSION.LTPA;
	
	private final BASE64Decoder decoder = new BASE64Decoder( );
		
	public UserMetadata( ) {		
	}
	
	/**
	 * Basic constructor
	 * @param plainToken
	 * @param ltpaVersion
	 * @throws Exception
	 */
	public UserMetadata( String plainToken, TokenLTPAFactory.LTPA_VERSION ltpaVersion ) throws Exception {
		this.ltpaVersion = ltpaVersion;
		
		String[] parts = plainToken.split( "\\%", 2 );
		this.expire = Long.parseLong( parts[1].split("\\%")[0] );
		String[] tokens = parts[0].split( "\\$" );
		
		for( int i=0; i < tokens.length; ++i ) {
			String nameValue[] = tokens[i].split(":", 2 );
			if ( "expire".equals( nameValue[0] ) ) {
				this.expire = Long.parseLong( nameValue[1] );
			} else if ( "host".equals( nameValue[0] ) ) {
				this.host = nameValue[1];
			} else if ( "java.naming.provider.url".equals( nameValue[0] ) ) {
				this.namingProvider = nameValue[1];
			} else if ( "port".equals( nameValue[0] ) ) {
				this.port = Integer.parseInt( nameValue[1] );
			} else if ( "process.serverName".equals( nameValue[0] ) ) {
				this.serverName = nameValue[1];
			} else if ( "security.authMechOID".equals( nameValue[0] ) ) {
				this.authenticationMethod = nameValue[1];
			} else if ( "type".equals( nameValue[0] ) ) {
				this.type = nameValue[1];
			} else if ( "u".equals( nameValue[0] ) ) {
				this.user = nameValue[1];
			} // else if
		} // for		
		this.signature =  decoder.decodeBuffer( plainToken.split( "%" )[2] );
	}
	
	/**
	 * Encode the user data to a plain LTPA token string
	 * @return
	 */
	public String getPlainUserMetadata( ) {
		StringBuilder str = new StringBuilder( );
		if ( ltpaVersion.equals( TokenLTPAFactory.LTPA_VERSION.LTPA2 ) ) {
			str.append("expire:").append(this.expire);
		} //	
		if ( this.host != null ) {
			str.append( "$").append("host:").append(this.host);
		} // if
		if ( this.namingProvider != null ) {			
			str.append( "$").append("java.naming.provider.url:").append(this.namingProvider);
		} // if		
		if ( this.port > 0 ) {
			str.append( "$").append("port:").append(this.port);
		} // if
		if ( this.serverName != null ) {
			str.append( "$").append("process.serverName:").append(this.serverName);
		} // if
		if ( this.authenticationMethod != null ) {
			str.append( "$").append("security.authMechOID:").append(this.authenticationMethod);
		} // if
		if ( this.type != null ) {
			str.append( "$").append("type:").append(this.type);
		} // if
		str.append( "$" ).append("u:").append(this.user);		
		return str.toString( );
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public String toString( ) {
		StringBuilder str = new StringBuilder( getPlainUserMetadata( ) );
		BASE64Encoder encoder = new BASE64Encoder( );
		str.append("%").append( this.expire ).append( "%" );
		str.append( encoder.encode( this.signature ).replaceAll("[\r\n]", "") );
		return str.toString( );
	}

	/**
	 * @return the expire
	 */
	public long getExpire() {
		return expire;
	}

	/**
	 * @param expire the expire to set
	 */
	public void setExpire(long expire) {
		this.expire = expire;
	}

	/**
	 * @return the user
	 */
	public String getUser() {
		return user;
	}

	/**
	 * @param user the user to set
	 */
	public void setUser(String user) {
		this.user = user;
	}

	/**
	 * @return the host
	 */
	public String getHost() {
		return host;
	}

	/**
	 * @param host the host to set
	 */
	public void setHost(String host) {
		this.host = host;
	}

	/**
	 * @return the port
	 */
	public int getPort() {
		return port;
	}

	/**
	 * @param port the port to set
	 */
	public void setPort(int port) {
		this.port = port;
	}

	/**
	 * @return the namingProvider
	 */
	public String getNamingProvider() {
		return namingProvider;
	}

	/**
	 * @param namingProvider the namingProvider to set
	 */
	public void setNamingProvider(String namingProvider) {
		this.namingProvider = namingProvider;
	}

	/**
	 * @return the serverName
	 */
	public String getServerName() {
		return serverName;
	}

	/**
	 * @param serverName the serverName to set
	 */
	public void setServerName(String serverName) {
		this.serverName = serverName;
	}

	/**
	 * @return the type
	 */
	public String getType() {
		return type;
	}

	/**
	 * @param type the type to set
	 */
	public void setType(String type) {
		this.type = type;
	}

	/**
	 * @return the signature
	 */
	public byte[] getSignature() {
		return signature.clone( );
	}

	/**
	 * @param signature the signature to set
	 */
	public void setSignature(byte[] signature) {
		this.signature = signature;
	}

	/**
	 * @return the ltpaVersion
	 */
	public TokenLTPAFactory.LTPA_VERSION getLtpaVersion() {
		return ltpaVersion;
	}

	/**
	 * @param ltpaVersion the ltpaVersion to set
	 */
	public void setLtpaVersion(TokenLTPAFactory.LTPA_VERSION ltpaVersion) {
		this.ltpaVersion = ltpaVersion;
	}	
}

