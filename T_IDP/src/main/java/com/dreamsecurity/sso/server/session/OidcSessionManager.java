package com.dreamsecurity.sso.server.session;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.dreamsecurity.sso.lib.jtm.DateTime;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.ha.SyncEvent;
import com.dreamsecurity.sso.server.ha.SyncMonitor;
import com.dreamsecurity.sso.server.token.OAuth2Code;
import com.dreamsecurity.sso.server.util.OIDCUtil;

public final class OidcSessionManager
{
	private static Logger log = LoggerFactory.getLogger(OidcSessionManager.class);

	private final Map<String, RootAuthSession> rootAuthSessionMap = new HashMap<String, RootAuthSession>();
	private final Map<String, OAuth2Code> oauth2CodeMap = new HashMap<String, OAuth2Code>();

	public static final int EVENT_OIDC_AUTH = 6;
	public static final int EVENT_OIDC_AUTHCODE_REDIRECT = 7;
	public static final int EVENT_OIDC_TOKEN_GENERATE = 8;
	public static final int EVENT_OIDC_TOKEN_REFRESH = 9;
	public static final int EVENT_OIDC_LOGOUT = 10;
	public static final int EVENT_REQ_OIDC_AUTHN = 11;

	private OidcSessionManager()
	{
	}

	private static class smSingleton
	{
		private static final OidcSessionManager instance = new OidcSessionManager();
	}

	public static OidcSessionManager getInstance()
	{
		return smSingleton.instance;
	}

	public Map<String, RootAuthSession> getRootAuthSessionMap()
	{
		return rootAuthSessionMap;
	}

	public RootAuthSession getRootAuthSession(String rootAuthSessionId)
	{
		RootAuthSession rootAuthSession = null;

		synchronized (rootAuthSessionMap) {
			rootAuthSession = rootAuthSessionMap.get(rootAuthSessionId);
		}

		return rootAuthSession;
	}

	public RootAuthSession generateRootAuthSession(HttpSession session)
	{
		RootAuthSession rootAuthSession = null;

		synchronized (rootAuthSessionMap) {
			String sessionId = OIDCUtil.generateUUID();
			rootAuthSession = new RootAuthSession(sessionId);
			rootAuthSessionMap.put(sessionId, rootAuthSession);
			session.setAttribute("DS_SESSION_ID", sessionId);
		}

		return rootAuthSession;
	}

	public void removeAuthSession(String rootAuthSessionId)
	{
		synchronized (rootAuthSessionMap) {
			rootAuthSessionMap.remove(rootAuthSessionId);
		}
		SyncMonitor.startMonitor();
		SyncMonitor.registOidcLogoutEvent(rootAuthSessionId);
	}

	public Map<String, OAuth2Code> getOauth2CodeMap()
	{
		return oauth2CodeMap;
	}

	public void addOAuth2Code(OAuth2Code oauth2Code)
	{
		synchronized (oauth2CodeMap) {
			oauth2CodeMap.put(oauth2Code.getId(), oauth2Code);
		}
	}

	public OAuth2Code getOAuth2Code(String id)
	{
		OAuth2Code oauth2Code = null;

		synchronized (oauth2CodeMap) {
			oauth2Code = oauth2CodeMap.get(id);
			if (oauth2Code != null) {
				oauth2CodeMap.remove(id);
			}
		}

		return oauth2Code;
	}

	public void applyEvents(SyncEvent event)
	{
		if (event == null) {
			return;
		}

		RootAuthSession rootAuthSession = null;
		OAuth2Code oauth2Code = null;
 
		switch (event.getEventid()) {
		case EVENT_OIDC_AUTH:
			rootAuthSession = event.getRootAuthSession();
			rootAuthSessionMap.remove(rootAuthSession.getSessionId());
			rootAuthSessionMap.put(rootAuthSession.getSessionId(), rootAuthSession);
			return;

		case EVENT_OIDC_AUTHCODE_REDIRECT:
			rootAuthSession = event.getRootAuthSession();
			oauth2Code = event.getOauth2Code();
			rootAuthSessionMap.remove(rootAuthSession.getSessionId());
			rootAuthSessionMap.put(rootAuthSession.getSessionId(), rootAuthSession);
			oauth2CodeMap.remove(oauth2Code.getId());
			oauth2CodeMap.put(oauth2Code.getId(), oauth2Code);
			return;

		case EVENT_OIDC_TOKEN_GENERATE:
			rootAuthSession = event.getRootAuthSession();
			oauth2Code = event.getOauth2Code();
			rootAuthSessionMap.remove(rootAuthSession.getSessionId());
			rootAuthSessionMap.put(rootAuthSession.getSessionId(), rootAuthSession);
			oauth2CodeMap.remove(oauth2Code.getId());
			return;

		case EVENT_OIDC_TOKEN_REFRESH:
			rootAuthSession = event.getRootAuthSession();
			rootAuthSessionMap.remove(rootAuthSession.getSessionId());
			rootAuthSessionMap.put(rootAuthSession.getSessionId(), rootAuthSession);
			return;

		case EVENT_OIDC_LOGOUT:
			rootAuthSessionMap.remove(event.getRootAuthSessionId());
			return;

		case EVENT_REQ_OIDC_AUTHN:
			rootAuthSession = rootAuthSessionMap.get(event.getRootAuthSessionId()) == null ? null
					: (RootAuthSession) rootAuthSessionMap.get(event.getRootAuthSessionId());

			if (rootAuthSession != null) {
				SyncMonitor.startMonitor();
				SyncMonitor.registOidcAuthEvent(rootAuthSession);
			}

			return;
		}
		
	}
}