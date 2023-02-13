package com.dreamsecurity.sso.agent.client;

import java.util.List;

public class ClientModel
{
	private String id;
	private String protocol;
	private String secret;
	private String responseType;
	private String grantType;
	private String nonce;
	private String pkce;
	private String refreshTokenUse;
	private String authEndpoint;
	private String tokenEndpoint;
	private String logoutEndpoint;
	private String introspectEndpoint;
	private String userinfoEndpoint;
	private String issuer;
	private List<Object> scopes;
	private List<Object> redirecturis;
	private String serverCert;

	public String getId()
	{
		return id;
	}
	public void setId(String id)
	{
		this.id = id;
	}

	public String getProtocol()
	{
		return protocol;
	}
	public void setProtocol(String protocol)
	{
		this.protocol = protocol;
	}

	public String getSecret()
	{
		return secret;
	}
	public void setSecret(String secret)
	{
		this.secret = secret;
	}

	public String getResponseType()
	{
		return responseType;
	}
	public void setResponseType(String responseType)
	{
		this.responseType = responseType;
	}

	public String getGrantType()
	{
		return grantType;
	}
	public void setGrantType(String grantType)
	{
		this.grantType = grantType;
	}

	public String getNonce()
	{
		return nonce;
	}
	public void setNonce(String nonce)
	{
		this.nonce = nonce;
	}

	public String getPkce()
	{
		return pkce;
	}
	public void setPkce(String pkce)
	{
		this.pkce = pkce;
	}

	public String getRefreshTokenUse()
	{
		return refreshTokenUse;
	}
	public void setRefreshTokenUse(String refreshTokenUse)
	{
		this.refreshTokenUse = refreshTokenUse;
	}

	public String getAuthEndpoint()
	{
		return authEndpoint;
	}
	public void setAuthEndpoint(String authEndpoint)
	{
		this.authEndpoint = authEndpoint;
	}

	public String getTokenEndpoint()
	{
		return tokenEndpoint;
	}
	public void setTokenEndpoint(String tokenEndpoint)
	{
		this.tokenEndpoint = tokenEndpoint;
	}

	public String getLogoutEndpoint()
	{
		return logoutEndpoint;
	}
	public void setLogoutEndpoint(String logoutEndpoint)
	{
		this.logoutEndpoint = logoutEndpoint;
	}

	public String getIntrospectEndpoint()
	{
		return introspectEndpoint;
	}
	public void setIntrospectEndpoint(String introspectEndpoint)
	{
		this.introspectEndpoint = introspectEndpoint;
	}

	public String getUserinfoEndpoint()
	{
		return userinfoEndpoint;
	}
	public void setUserinfoEndpoint(String userinfoEndpoint)
	{
		this.userinfoEndpoint = userinfoEndpoint;
	}

	public List<Object> getScopes()
	{
		return scopes;
	}
	public void setScopes(List<Object> scopes)
	{
		this.scopes = scopes;
	}

	public List<Object> getRedirecturis()
	{
		return redirecturis;
	}
	public void setRedirecturis(List<Object> redirecturis)
	{
		this.redirecturis = redirecturis;
	}

	public String getServerCert()
	{
		return serverCert;
	}
	public void setServerCert(String serverCert)
	{
		this.serverCert = serverCert;
	}
	public String getIssuer() {
		return issuer;
	}
	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}
	
}