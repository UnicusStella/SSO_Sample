package com.dreamsecurity.sso.server.session;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.metadata.MetadataRepository;

public class SubAuthSession implements Serializable
{
	private static final long serialVersionUID = -5192288150064463025L;

	private static Logger log = LoggerFactory.getLogger(MetadataRepository.class);

	public Map<String, String> attributes = new HashMap<String, String>();

	private String sessionId;
	private String idJwt;
	private String accessJwt;
	private String refreshJwt;

	public SubAuthSession(String subAuthSessionId)
	{
		this.sessionId = subAuthSessionId;
	}

	public String getSessionId()
	{
		return sessionId;
	}

	public String getIdJwt()
	{
		return idJwt;
	}

	public void setIdJwt(String idJwt)
	{
		this.idJwt = idJwt;
	}

	public String getAccessJwt()
	{
		return accessJwt;
	}

	public void setAccessJwt(String accessJwt)
	{
		this.accessJwt = accessJwt;
	}

	public String getRefreshJwt()
	{
		return refreshJwt;
	}

	public void setRefreshJwt(String refreshJwt)
	{
		this.refreshJwt = refreshJwt;
	}
}