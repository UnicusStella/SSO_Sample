package com.dreamsecurity.sso.server.api.admin.vo;

public class ClientVO
{
	private String id;
	private String name;
	private String protocol;
	private String enabled;
	private String secret;
	private String responseType;
	private String grantType;
	private String nonce;
	private String pkce;
	private String refreshTokenUse;
	private String codeLifespan;
	private String tokenLifespan;
	private String refreshTokenLifespan;
	private String serverCert;
	private String scope;
	private String redirectUri;

	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getProtocol() {
		return protocol;
	}
	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}
	public String getEnabled() {
		return enabled;
	}
	public void setEnabled(String enabled) {
		this.enabled = enabled;
	}
	public String getSecret() {
		return secret;
	}
	public void setSecret(String secret) {
		this.secret = secret;
	}
	public String getResponseType() {
		return responseType;
	}
	public void setResponseType(String responseType) {
		this.responseType = responseType;
	}
	public String getGrantType() {
		return grantType;
	}
	public void setGrantType(String grantType) {
		this.grantType = grantType;
	}
	public String getNonce() {
		return nonce;
	}
	public void setNonce(String nonce) {
		this.nonce = nonce;
	}
	public String getPkce() {
		return pkce;
	}
	public void setPkce(String pkce) {
		this.pkce = pkce;
	}
	public String getRefreshTokenUse() {
		return refreshTokenUse;
	}
	public void setRefreshTokenUse(String refreshTokenUse) {
		this.refreshTokenUse = refreshTokenUse;
	}
	public String getCodeLifespan() {
		return codeLifespan;
	}
	public void setCodeLifespan(String codeLifespan) {
		this.codeLifespan = codeLifespan;
	}
	public String getTokenLifespan() {
		return tokenLifespan;
	}
	public void setTokenLifespan(String tokenLifespan) {
		this.tokenLifespan = tokenLifespan;
	}
	public String getRefreshTokenLifespan() {
		return refreshTokenLifespan;
	}
	public void setRefreshTokenLifespan(String refreshTokenLifespan) {
		this.refreshTokenLifespan = refreshTokenLifespan;
	}
	public String getServerCert() {
		return serverCert;
	}
	public void setServerCert(String serverCert) {
		this.serverCert = serverCert;
	}
	public String getScope() {
		return scope;
	}
	public void setScope(String scope) {
		this.scope = scope;
	}
	public String getRedirectUri() {
		return redirectUri;
	}
	public void setRedirectUri(String redirectUri) {
		this.redirectUri = redirectUri;
	}
}