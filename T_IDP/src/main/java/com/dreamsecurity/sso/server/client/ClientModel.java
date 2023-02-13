package com.dreamsecurity.sso.server.client;

import java.util.List;

import com.dreamsecurity.sso.server.api.admin.vo.ClientVO;

public class ClientModel
{
	private ClientVO clientInfo;
	private List<Object> scopes;
	private List<Object> redirecturis;

	public ClientVO getClientInfo()
	{
		return clientInfo;
	}

	public void setClientInfo(ClientVO clientInfo)
	{
		this.clientInfo = clientInfo;
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
}