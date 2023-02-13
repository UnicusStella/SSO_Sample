package com.dreamsecurity.sso.server.token;

import java.io.Serializable;

import com.dreamsecurity.sso.lib.jtm.DateTime;
import com.dreamsecurity.sso.server.util.OIDCUtil;

public class OAuth2Code implements Serializable
{
	private static final long serialVersionUID = 8911707699400138420L;

	private String id;
	private String subAuthSessionId;
	private String rootAuthSessionId;
	private DateTime expDate;

	public OAuth2Code(String rootAuthSessionId, String subAuthSessionId, DateTime expDate)
	{
		this.id = OIDCUtil.generateUUID();
		this.subAuthSessionId = subAuthSessionId;
		this.rootAuthSessionId = rootAuthSessionId;
		this.expDate = expDate;
	}

	public String getId()
	{
		return id;
	}

	public String getSubSessionId()
	{
		return subAuthSessionId;
	}

	public String getRootSessionId()
	{
		return rootAuthSessionId;
	}

	public DateTime getExpDate()
	{
		return expDate;
	}
}