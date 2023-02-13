package com.dreamsecurity.sso.agent.ha;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.servlet.http.HttpSession;

import com.dreamsecurity.sso.agent.api.AuditService;
import com.dreamsecurity.sso.agent.log.Logger;
import com.dreamsecurity.sso.agent.log.LoggerFactory;
import com.dreamsecurity.sso.agent.util.Util;

public final class SyncManager
{
	private static Logger log = LoggerFactory.getInstance().getLogger(SyncManager.class);

	private static final SyncManager instance = new SyncManager();

	private final Map<String, Object> httpsessionMap = new HashMap<String, Object>();
	private final Map<String, String> challengeMap = new HashMap<String, String>();

	private SyncManager()
	{
	}

	public static SyncManager getInstance()
	{
		return instance;
	}

	public Map<String, String> getChallengeMap()
	{
		return challengeMap;
	}

	public void addHttpSession(String user, HttpSession httpSession)
	{
		/*******************************
		 * httpsessionMap<ssouser, sessions<sessionId, httpSession>>
		 */
		Map<String, Object> sessions = (Map<String, Object>) httpsessionMap.get(user);

		if (sessions == null) {
			synchronized (httpsessionMap) {
				sessions = (Map<String, Object>) httpsessionMap.get(user);

				if (sessions == null) {
					sessions = new HashMap<String, Object>();
					httpsessionMap.put(user, sessions);
				}
			}
		}

		if (!sessions.containsKey(httpSession.getId())) {
			sessions.put(httpSession.getId(), httpSession);
			log.debug("### add HTTPSession : " + user + " - ID : " + httpSession.getId() + " - size : " + sessions.size());
		}
	}

	public void logoutSession(String user)
	{
		Map<String, Object> httpsessions;

		synchronized (httpsessionMap) {
			httpsessions = (Map<String, Object>) httpsessionMap.get(user);
		}

		if (httpsessions == null) {
			return;
		}

		Iterator<?> iterator = httpsessions.values().iterator();
		while (iterator.hasNext()) {
			HttpSession httpsession = (HttpSession) iterator.next();
			if (httpsession != null) {
				try {
					httpsession.invalidate();
				}
				catch (Exception e) {
					log.debug("### httpsession invalidated");
				}
			}
		}
	}

	public void setChallenge(String key, String value)
	{
		challengeMap.put(key, value);

		SyncEvent event = new SyncEvent(SyncEvent.EVENT_SET_CHLG, System.currentTimeMillis(), key, value);
		SyncMonitor.sendEvent(event);
	}

	public void removeChallenge(String key)
	{
		challengeMap.remove(key);

		SyncEvent event = new SyncEvent(SyncEvent.EVENT_DEL_CHLG, System.currentTimeMillis(), key, "");
		SyncMonitor.sendEvent(event);
	}

	public void applyEvents(SyncEvent event)
	{
		if (event == null) {
			return;
		}

		log.debug("### Event Recieve : " + event);

		switch (event.getEventid()) {
		case SyncEvent.EVENT_INTEGRITY:
			AuditService auditApi = new AuditService();
			auditApi.integrityTest(event.getValue());
			return;

		case SyncEvent.EVENT_LOGIN:
			return;

		case SyncEvent.EVENT_LOGOUT:
			return;

		case SyncEvent.EVENT_SET_CHLG:
			if (!Util.isEmpty(event.getKey()) && !Util.isEmpty(event.getValue())) {
				challengeMap.put(event.getKey(), event.getValue());
			}
			return;

		case SyncEvent.EVENT_DEL_CHLG:
			if (!Util.isEmpty(event.getKey())) {
				challengeMap.remove(event.getKey());
			}
			return;
		}
	}

}
