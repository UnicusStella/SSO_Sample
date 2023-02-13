package com.dreamsecurity.sso.server.session;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.dreamsecurity.sso.lib.jtm.DateTime;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.metadata.MetadataRepository;
import com.dreamsecurity.sso.server.util.OIDCUtil;

public class RootAuthSession implements Serializable
{
	private static final long serialVersionUID = -6361479133875075837L;

	private static Logger log = LoggerFactory.getLogger(MetadataRepository.class);

	public Map<String, String> attributes = new HashMap<String, String>();
	private Map<String, SubAuthSession> SubAuthSessionMap = new HashMap<String, SubAuthSession>();
	private String sessionId;
	private DateTime expDate;
	private String identityJwt;
	List<String> logoutUrls = new ArrayList<String>();

	public RootAuthSession(String id)
	{
		this.sessionId = id;
	}

	public String getSessionId()
	{
		return sessionId;
	}

	public SubAuthSession generateSubAuthSession()
	{
		SubAuthSession subAuthSession = null;

		synchronized (SubAuthSessionMap) {
			String subAuthSessionId = OIDCUtil.generateUUID();
			subAuthSession = new SubAuthSession(subAuthSessionId);
			SubAuthSessionMap.put(subAuthSessionId, subAuthSession);
		}

		return subAuthSession;
	}

	public SubAuthSession getSubAuthSession(String subAuthSessionId)
	{
		SubAuthSession subAuthSession = null;

		synchronized (SubAuthSessionMap) {
			subAuthSession = SubAuthSessionMap.get(subAuthSessionId);
		}

		return subAuthSession;
	}

	public DateTime getExpDate()
	{
		return expDate;
	}

	public void setExpDate(DateTime expDate)
	{
		this.expDate = expDate;
	}

	public List<String> getLogoutUrls()
	{
		return logoutUrls;
	}

	public void addLogoutUrl(String logoutUrl)
	{
		logoutUrls.add(logoutUrl);
	}

	public String getIdentityJwt()
	{
		return identityJwt;
	}

	public void setIdentityJwt(String identityJwt)
	{
		this.identityJwt = identityJwt;
	}
}