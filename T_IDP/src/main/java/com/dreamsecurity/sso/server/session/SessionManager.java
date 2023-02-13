package com.dreamsecurity.sso.server.session;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.dreamsecurity.sso.lib.dss.s2.core.AuthnContextClassRef;
import com.dreamsecurity.sso.lib.dss.s2.core.AuthnRequest;
import com.dreamsecurity.sso.lib.jtm.DateTime;
import com.dreamsecurity.sso.lib.jtm.DateTimeZone;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.ha.SyncEvent;
import com.dreamsecurity.sso.server.ha.SyncMonitor;
import com.dreamsecurity.sso.server.util.Util;

public final class SessionManager
{
	private static Logger log = LoggerFactory.getLogger(SessionManager.class);

	private final Map<String, Object> sessionMap = new HashMap<String, Object>();
	private final Map<String, Object> authcodeMap = new HashMap<String, Object>();

	private final Map<String, DateTime> authnMap = new HashMap<String, DateTime>();
	private final Map<String, DateTime> authnNLMap = new HashMap<String, DateTime>();

	private final Map<String, String> licenseMap = new HashMap<String, String>();

	public static final int EVENT_INTEGRITY = 0;
	public static final int EVENT_LOGIN = 1;
	public static final int EVENT_LOGOUT = 2;
	public static final int EVENT_AUTHN = 3;
	public static final int EVENT_REQ_AUTHN = 4;
	public static final int EVENT_BLOCK = 5;

	private SessionManager()
	{
	}

	private static class smSingleton
	{
		private static final SessionManager instance = new SessionManager();
	}

	public static SessionManager getInstance()
	{
		return smSingleton.instance;
	}

	public Map<String, Object> getSessionMap()
	{
		return sessionMap;
	}

	public Map<String, Object> getAuthcodeMap()
	{
		return authcodeMap;
	}

	public Map<String, DateTime> getAuthnMap()
	{
		return authnMap;
	}

	public Map<String, DateTime> getAuthnNLMap()
	{
		return authnNLMap;
	}

	public Map<String, String> getLicenseMap()
	{
		return licenseMap;
	}

	public boolean addAuthnRequest(AuthnRequest authnRequest)
	{
		boolean result = false;
		String id = authnRequest.getProviderName() + authnRequest.getID();

		if (authnMap.containsKey(id)) {  // 동일 인증 요청 패킷 재시도 방지
			result = true;
		}

		if (!result) {
			authnMap.put(id, authnRequest.getIssueInstant());
		}

		return result;
	}

	public boolean addNLAuthnRequest(String id, DateTime issueTime)
	{
		boolean result = false;

		if (authnNLMap.containsKey(id)) {  // 동일 요청 패킷 재시도 방지
			result = true;
		}

		if (!result) {
			authnNLMap.put(id, issueTime);
		}

		return result;
	}

	public void addAuthcodeMap(String authCode, String userId, String provider, String deviceType, String deviceId, String authnData)
	{
		DateTime issueInstant = new DateTime(DateTimeZone.UTC);

		AuthnIssue authnIssue = new AuthnIssue(userId, provider, deviceId, "", authnData, issueInstant);
		authcodeMap.put(authCode, authnIssue);

		// 다중화 서버 간 동기화
		SyncMonitor.startMonitor();
		SyncMonitor.registAuthnEvent(userId, provider, issueInstant, authnData, authCode, deviceType, deviceId);
	}

	public void logoutSession(String userId, String authCode)
	{
		synchronized (sessionMap) {
			sessionMap.remove(userId);
		}

		if (!Util.isEmpty(authCode)) {
			AuthnIssue authnIssue = (AuthnIssue) authcodeMap.get(authCode);

			if (authnIssue != null) {
				try {
					Util.zeroize(authnIssue.getAuthnInfo());
				}
				catch (Exception e) {
					e.printStackTrace();
				}

				authcodeMap.remove(authCode);
			}
		}

		// 다중화 서버 간 동기화
		SyncMonitor.startMonitor();
		SyncMonitor.registLogoutEvent(userId, authCode);
	}

	public void logoutSessionByEvent(String userId, String authCode)
	{
		synchronized (sessionMap) {
			sessionMap.remove(userId);
		}

		if (!Util.isEmpty(authCode)) {
			AuthnIssue authnIssue = (AuthnIssue) authcodeMap.get(authCode);

			if (authnIssue != null) {
				try {
					Util.zeroize(authnIssue.getAuthnInfo());
				}
				catch (Exception e) {
					e.printStackTrace();
				}

				authcodeMap.remove(authCode);
			}
		}
	}

	public AuthSession getSession(String ssouser)
	{
		if (!sessionMap.containsKey(ssouser)) {
			synchronized (sessionMap) {
				if (!sessionMap.containsKey(ssouser)) {
					List<Object> authSessionList = new ArrayList<Object>();
					authSessionList.add(new AuthSession(ssouser));
					sessionMap.put(ssouser, authSessionList);
				}
			}
		}

		List<?> authSessions = (List<?>) sessionMap.get(ssouser);
		return (AuthSession) authSessions.get(authSessions.size() - 1);
	}

	/*
	 * @param ssouser - SSO Token의 userid
	 * @param authSession - IDP Session의 authSession
	 * @param authnContextClassList - authRequest에서 추출한 list
	 */
	public boolean compareSession(String ssouser, AuthSession authSession, List<?> authnContextClassList)
	{
		boolean result = false;

		if (Util.isEmpty(ssouser) || authSession == null || sessionMap.get(ssouser) == null) {
			return result;
		}

		// AuthSession List
		List<?> list = (List<?>) sessionMap.get(ssouser);

		for (int i = 0; i < list.size(); i++) {
			AuthSession authSess = (AuthSession) list.get(i);
			if (authSess == null) {
				continue;
			}

			if (isRequestedAuthContext(authSession, authnContextClassList)
					&& (authSession.equals(authSess) || isRequestedAuthContext(authSess, authnContextClassList))) {
				result = true;
				break;
			}
		}

		return result;
	}

	public boolean compareSession(String ssouser, AuthSession authSession)
	{
		boolean result = false;

		if (Util.isEmpty(ssouser) || authSession == null || sessionMap.get(ssouser) == null) {
			return result;
		}

		// AuthSession List
		List<?> list = (List<?>) sessionMap.get(ssouser);

		for (int i = 0; i < list.size(); i++) {
			AuthSession authSess = (AuthSession) list.get(i);

			if (authSess == null) {
				continue;
			}

			if (authSession.equals(authSess)) {
				result = true;
				break;
			}
		}

		return result;
	}

	private boolean isRequestedAuthContext(AuthSession authSessionP, List<?> authClassList)
	{
		Set<?> authedList = authSessionP.getAuthClassList();

		for (int i = 0; i < authClassList.size(); i++) {
			if (authedList.contains(((AuthnContextClassRef) authClassList.get(i)).getAuthnContextClassRef())) {
				return true;
			}
		}

		return false;
	}

	public Map<String, Object> getSessionUserMap()
	{
		HashMap<String, Object> resultMap = new HashMap<String, Object>();

		Iterator<String> iterator = sessionMap.keySet().iterator();

		while (iterator.hasNext()) {
			String user = iterator.next();
			List<?> authSessions = (List<?>) sessionMap.get(user);
			AuthSession session = (AuthSession) authSessions.get(0);
			resultMap.put(user, session.getRemoteSessionProviderNames());
		}

		return resultMap;
	}

	public Map<String, Object> getSessionProviderMap()
	{
		HashMap<String, Object> resultMap = new HashMap<String, Object>();

		Iterator<String> iterator = sessionMap.keySet().iterator();

		while (iterator.hasNext()) {
			String user = iterator.next();
			List<?> authSessions = (List<?>) sessionMap.get(user);
			AuthSession session = (AuthSession) authSessions.get(0);
			List<?> providerNames = session.getRemoteSessionProviderNames();

			for (int j = 0; j < providerNames.size(); j++) {
				String prov = (String) providerNames.get(j);

				if (!resultMap.containsKey(prov)) {
					resultMap.put(prov, new ArrayList<Object>());
				}

				((List) resultMap.get(prov)).add(user);
			}
		}

		return resultMap;
	}

	public void applyEvents(SyncEvent event)
	{
		if (event == null) {
			return;
		}

		switch (event.getEventid()) {
		case EVENT_LOGIN:
			AuthSession session = getSession(event.getId());
			session.addRemoteSessionByEvent(event.getProviderId(), event.getIssueInstant(),
					event.getAuthnContextClassRef(), event.getProvSessionId());
			return;

		case EVENT_LOGOUT:
			logoutSessionByEvent(event.getId(), event.getAuthcode());
			return;

		case EVENT_AUTHN:
			AuthnIssue authnIssue = new AuthnIssue(event.getId(), event.getProviderId(),
					event.getDeviceId(), "", event.getAuthnInfo(), event.getIssueInstant());
			authcodeMap.put(event.getAuthcode(), authnIssue);
			return;

		case EVENT_REQ_AUTHN:
			AuthnIssue authnIssue2 = authcodeMap.get(event.getAuthcode()) == null ? null : (AuthnIssue) authcodeMap.get(event.getAuthcode());
			if (authnIssue2 != null ) {
				SyncMonitor.startMonitor();
				SyncMonitor.registAuthnEvent(authnIssue2.getUserId(), authnIssue2.getProviderName(), authnIssue2.getIssueTime(),
						authnIssue2.getAuthnInfo(), event.getAuthcode(), "", authnIssue2.getDeviceId());
			}
			return;

		case EVENT_BLOCK:
			AuthnIssue authnIssue3 = authcodeMap.get(event.getAuthcode()) == null ? null : (AuthnIssue) authcodeMap.get(event.getAuthcode());
			if (authnIssue3 != null && authnIssue3.getUserId().equals(event.getId())) {
				authnIssue3.setBlockId(event.getBlockId());
			}
			return;

		}
	}

	public void clearAuthnInfo()
	{
		Iterator<Entry<String,Object>> iterAuth = authcodeMap.entrySet().iterator();

		while (iterAuth.hasNext()) {
			Entry<String,Object> entry = (Entry<String,Object>) iterAuth.next();
			AuthnIssue authnIssue = (AuthnIssue) entry.getValue();

			try {
				Util.zeroize(authnIssue.getAuthnInfo());
			}
			catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
}