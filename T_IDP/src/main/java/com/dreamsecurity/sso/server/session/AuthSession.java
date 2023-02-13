package com.dreamsecurity.sso.server.session;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.dreamsecurity.sso.lib.jtm.DateTime;
import com.dreamsecurity.sso.lib.dss.s2.core.Assertion;
import com.dreamsecurity.sso.lib.dss.s2.core.AuthnRequest;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.ha.SyncMonitor;
import com.dreamsecurity.sso.server.metadata.MetadataRepository;

public class AuthSession implements Serializable
{
	private static Logger log = LoggerFactory.getLogger(MetadataRepository.class);

	private static final long serialVersionUID = -6500498032686303937L;

	private String userId;

    private Map<String, Object> sessionByProvID = new HashMap<String, Object>();
    private Map<String, Object> sessionByAuthClass = new HashMap<String, Object>();
    
	public AuthSession(String userId)
	{
		this.userId = userId;
	}

	public Map<String, Object> getSessionByProvID()
	{
		return this.sessionByProvID;
	}

	public Map<String, Object> getSessionByAuthClass()
	{
		return this.sessionByAuthClass;
	}

	public void addRemoteSessionByAuthnRequest(AuthnRequest authnRequest, String remoteSessionId)
	{
		RemoteSession remoteSession = new RemoteSession(authnRequest, remoteSessionId);
		sessionByProvID.put(remoteSession.getProviderId(), remoteSession);
		log.debug(" ## Add RemoteSession : " + remoteSession.hashCode() + "remoteSessionId : " + remoteSessionId);

		RemoteSession befSession = (RemoteSession) sessionByProvID.get(remoteSession.getProviderId());
		if (befSession != null) {
			Object o = this.sessionByAuthClass.get(befSession.getAuthnContextClassRef());
			if (o != null) {
				((List) o).remove(befSession);
			}
		}

		String classRef = remoteSession.getAuthnContextClassRef();
		if (!sessionByAuthClass.containsKey(classRef)) {
			sessionByAuthClass.put(classRef, new ArrayList());
		}

		((List) sessionByAuthClass.get(classRef)).add(remoteSession);
	}

	public void addRemoteSessionByAssertion(String userId, String providerName, Assertion assertion, String provSessionId)
	{
		RemoteSession remoteSession = new RemoteSession(providerName, assertion, provSessionId);

		RemoteSession befSession = (RemoteSession) sessionByProvID.get(remoteSession.getProviderId());
		if (befSession != null) {
			Object o = this.sessionByAuthClass.get(befSession.getAuthnContextClassRef());
			if (o != null) {
				((List) o).remove(befSession);
			}
		}

		sessionByProvID.put(remoteSession.getProviderId(), remoteSession);

		String classRef = remoteSession.getAuthnContextClassRef();
		if (!sessionByAuthClass.containsKey(classRef)) {
			sessionByAuthClass.put(classRef, new ArrayList());
		}

		((List) sessionByAuthClass.get(classRef)).add(remoteSession);

		// 다중화 서버 간 동기화
		SyncMonitor.startMonitor();
		SyncMonitor.registLoginEvent(userId, providerName,	remoteSession.getIssueInstant(),
				remoteSession.getAuthnContextClassRef(), remoteSession.getProvSessionId());
	}

	public void addRemoteSessionByS2S(String userId, String providerName, DateTime issueInstant, String authnContextClassRef, String provSessionId)
	{
		RemoteSession remoteSession = new RemoteSession(providerName, issueInstant, authnContextClassRef, provSessionId);

		RemoteSession befSession = (RemoteSession) sessionByProvID.get(remoteSession.getProviderId());
		if (befSession != null) {
			Object o = this.sessionByAuthClass.get(befSession.getAuthnContextClassRef());
			if (o != null) {
				((List) o).remove(befSession);
			}
		}

		sessionByProvID.put(remoteSession.getProviderId(), remoteSession);

		String classRef = remoteSession.getAuthnContextClassRef();
		if (!sessionByAuthClass.containsKey(classRef)) {
			sessionByAuthClass.put(classRef, new ArrayList());
		}

		((List) sessionByAuthClass.get(classRef)).add(remoteSession);

		// 다중화 서버 간 동기화
		SyncMonitor.startMonitor();
		SyncMonitor.registLoginEvent(userId, providerName,	remoteSession.getIssueInstant(),
				remoteSession.getAuthnContextClassRef(), remoteSession.getProvSessionId());
	}

	public void addRemoteSessionByOidc(String userId, String providerName, DateTime issueInstant, String authnContextClassRef, String provSessionId)
	{
		RemoteSession remoteSession = new RemoteSession(providerName, issueInstant, authnContextClassRef, provSessionId);

		RemoteSession befSession = (RemoteSession) sessionByProvID.get(remoteSession.getProviderId());
		if (befSession != null) {
			Object o = this.sessionByAuthClass.get(befSession.getAuthnContextClassRef());
			if (o != null) {
				((List) o).remove(befSession);
			}
		}

		sessionByProvID.put(remoteSession.getProviderId(), remoteSession);

		String classRef = remoteSession.getAuthnContextClassRef();
		if (!sessionByAuthClass.containsKey(classRef)) {
			sessionByAuthClass.put(classRef, new ArrayList());
		}

		((List) sessionByAuthClass.get(classRef)).add(remoteSession);

		// 다중화 서버 간 동기화
		SyncMonitor.startMonitor();
		SyncMonitor.registLoginEvent(userId, providerName,	remoteSession.getIssueInstant(),
				remoteSession.getAuthnContextClassRef(), remoteSession.getProvSessionId());
	}

	public void addRemoteSessionByEvent(String providerName, DateTime issueInstant, String authnContextClassRef, String provSessionId)
	{
		RemoteSession remoteSession = new RemoteSession(providerName, issueInstant, authnContextClassRef, provSessionId);

		RemoteSession befSession = (RemoteSession) sessionByProvID.get(remoteSession.getProviderId());
		if (befSession != null) {
			Object o = this.sessionByAuthClass.get(befSession.getAuthnContextClassRef());
			if (o != null) {
				((List) o).remove(befSession);
			}
		}

		sessionByProvID.put(remoteSession.getProviderId(), remoteSession);

		String classRef = remoteSession.getAuthnContextClassRef();
		if (!sessionByAuthClass.containsKey(classRef)) {
			sessionByAuthClass.put(classRef, new ArrayList());
		}

		((List) sessionByAuthClass.get(classRef)).add(remoteSession);
	}

	public RemoteSession getRemoteSessionByProvider(String provider)
	{
		return (RemoteSession) sessionByProvID.get(provider);
	}

	public List getRemoteSessionProviderNames()
	{
		ArrayList arrayList = new ArrayList();

		Iterator iterator = sessionByProvID.keySet().iterator();
		while (iterator.hasNext()) {
			arrayList.add(iterator.next());
		}

		return arrayList;
	}

	public List getRemoteSessionListByAuthClass(String classRef)
	{
		return (List) sessionByAuthClass.get(classRef);
	}

	public Set getAuthClassList()
	{
		return sessionByAuthClass.keySet();
	}

	public void removeRemoteSession(String provider)
	{
		RemoteSession session = (RemoteSession) sessionByProvID.remove(provider);
		if (session == null) {
			return;
		}

		Object o = sessionByAuthClass.get(session.getAuthnContextClassRef());
		if (o != null) {
			((List) o).clear();
		}
	}

	public String getUserId()
	{
		return userId;
	}
}