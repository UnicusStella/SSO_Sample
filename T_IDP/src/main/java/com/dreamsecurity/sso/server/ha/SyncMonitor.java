package com.dreamsecurity.sso.server.ha;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;

import com.dreamsecurity.sso.lib.jtm.DateTime;
import com.dreamsecurity.sso.lib.jtm.DateTimeZone;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.api.audit.AuditController;
import com.dreamsecurity.sso.server.client.ClientRepository;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.provider.EnvironInform;
import com.dreamsecurity.sso.server.session.OidcSessionManager;
import com.dreamsecurity.sso.server.session.RootAuthSession;
import com.dreamsecurity.sso.server.session.SessionManager;
import com.dreamsecurity.sso.server.token.OAuth2Code;
import com.dreamsecurity.sso.server.util.Util;

public class SyncMonitor implements Runnable
{
	private static Logger log = LoggerFactory.getLogger(SyncMonitor.class);

	private static final SyncMonitor instance = new SyncMonitor();

	private static boolean bReady = false;

	int port = 0;
	List<Object> ipList;

	public static final int EVENT_INTEGRITY = 0;
	public static final int EVENT_LOGIN = 1;
	public static final int EVENT_LOGOUT = 2;
	public static final int EVENT_AUTHN = 3;
	public static final int EVENT_REQ_AUTHN = 4;
	public static final int EVENT_BLOCK = 5;

	// OIDC
	public static final int EVENT_OIDC_AUTH = 6;
	public static final int EVENT_OIDC_AUTHCODE_REDIRECT = 7;
	public static final int EVENT_OIDC_TOKEN_GENERATE = 8;
	public static final int EVENT_OIDC_TOKEN_REFRESH = 9;
	public static final int EVENT_OIDC_LOGOUT = 10;
	public static final int EVENT_REQ_OIDC_AUTHN = 11;
	public static final int EVENT_OIDC_CLIENT_RELOAD = 12;

	private SyncMonitor()
	{
		SSOConfig config = SSOConfig.getInstance();

		port = config.getInt("ha.listen.port", 0);
		ipList = config.getList("ha.send.ip", null);

		if (ipList == null) {
			port = 0;
		}
		else {
			if (ipList.size() == 1 && Util.isEmpty((String) ipList.get(0))) {
				port = 0;
			}
			else {
				log.debug("### Sync IP  : {}", this.ipList.toString());
				log.debug("### Sync Port: {}", this.port);
			}
		}
	}

	public static boolean isReady()
	{
		return bReady;
	}

	public static void startMonitor()
	{
		if (instance.port == 0) {
			return;
		}

		if (!bReady) {
			synchronized (instance) {
				if (!bReady) {
					log.debug("### SyncMonitor Start");
					new Thread(instance).start();
				}
			}
		}
	}

	public void run()
	{
		ServerSocket serverSocket = null;

		try {
			serverSocket = new ServerSocket(port);

			while (true) {
				Socket socket = serverSocket.accept();
				receiveEvent(socket);
				bReady = true;
			}
		}
		catch (Exception e) {
			// e.printStackTrace();
		}
		finally {
			try {
				if (serverSocket != null) {
					serverSocket.close();
				}
			}
			catch (IOException e) {
				// e.printStackTrace();
			}

			bReady = false;
		}
	}

	private void receiveEvent(Socket socket)
	{
		try {
			ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());
			SyncEvent event = (SyncEvent) inputStream.readObject();
			socket.close();

			log.debug("### receiveEvent() Data : {}", event.toString());

			switch (event.getEventid()) {
			case EVENT_INTEGRITY:
				AuditController auditApi = new AuditController();
				auditApi.integrityIDPTest(event.getId(), event.getDetail());
				return;

			case EVENT_LOGIN:
			case EVENT_LOGOUT:
			case EVENT_AUTHN:
			case EVENT_REQ_AUTHN:
			case EVENT_BLOCK:
				SessionManager.getInstance().applyEvents(event);
				return;

			case EVENT_OIDC_AUTH:
			case EVENT_OIDC_AUTHCODE_REDIRECT:
			case EVENT_OIDC_TOKEN_GENERATE:
			case EVENT_OIDC_TOKEN_REFRESH:
			case EVENT_OIDC_LOGOUT:
			case EVENT_REQ_OIDC_AUTHN:
				OidcSessionManager.getInstance().applyEvents(event);
				return;

			case EVENT_OIDC_CLIENT_RELOAD:
				ClientRepository.getInstance().applyEvents(event);
				EnvironInform.getInstance().licenseInit();
				return;
			}
		}
		catch (Exception e) {
			log.debug("### receiveEvent() Exception : ", e);
		}
	}

	public static void sendEvent(final SyncEvent event)
	{
		if (instance.port == 0) {
			return;
		}

		for (int i = 0; i < instance.ipList.size(); i++) {
			log.debug("### sendEvent() Data : {}", event.toString());

			final String ip = (String) instance.ipList.get(i);
			log.debug("### sendEvent() IP[{}] : {}", i, ip);

			if (Util.isEmpty(ip)) {
				continue;
			}

			new Thread()
			{
				public void run()
				{
					try {
						Socket socket = new Socket();
						socket.connect(new InetSocketAddress(ip, instance.port), 3000);
						ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
						outputStream.writeObject(event);
						socket.close();
					}
					catch (IOException e) {
						log.debug("### sendEvent() Exception : ", e);
					}
				}
			}.start();
		}
	}

	public static void sendIntegrityEvent(String id, String detail)
	{
		SyncEvent event = new SyncEvent(EVENT_INTEGRITY, System.currentTimeMillis(), detail, id, "", new DateTime(DateTimeZone.UTC), "", "", "", "",
				"", "", "", null, null, "");
		sendEvent(event);
	}

	public static void registLoginEvent(String id, String providerId, DateTime issueInstant, String authnContextClassRef, String provSessionId)
	{
		SyncEvent event = new SyncEvent(EVENT_LOGIN, System.currentTimeMillis(), "", id, providerId, issueInstant, authnContextClassRef,
				provSessionId, "", "", "", "", "", null, null, "");
		sendEvent(event);
	}

	public static void registLogoutEvent(String id, String authCode)
	{
		SyncEvent event = new SyncEvent(EVENT_LOGOUT, System.currentTimeMillis(), "", id, "", new DateTime(DateTimeZone.UTC), "", "", "", authCode,
				"", "", "", null, null, "");
		sendEvent(event);
	}

	public static void registAuthnEvent(String id, String provider, DateTime issueInstant, String authnData, String authCode, String deviceType,
			String deviceId)
	{
		SyncEvent event = new SyncEvent(EVENT_AUTHN, System.currentTimeMillis(), "", id, "", issueInstant, "", "", authnData, authCode, deviceType,
				deviceId, "", null, null, "");
		sendEvent(event);
	}

	public static void requestAuthcodeEvent(String authCode)
	{
		SyncEvent event = new SyncEvent(EVENT_REQ_AUTHN, System.currentTimeMillis(), "", "none", "", new DateTime(DateTimeZone.UTC), "", "", "",
				authCode, "", "", "", null, null, "");
		sendEvent(event);
	}

	public static void registBlockEvent(String id, String authCode, String blockId)
	{
		SyncEvent event = new SyncEvent(EVENT_BLOCK, System.currentTimeMillis(), "", id, "", new DateTime(DateTimeZone.UTC), "", "", "", authCode, "",
				"", blockId, null, null, "");
		sendEvent(event);
	}

	public static void registOidcAuthEvent(RootAuthSession rootAuthSession)
	{
		SyncEvent event = new SyncEvent(EVENT_OIDC_AUTH, System.currentTimeMillis(), "", "none", "", new DateTime(DateTimeZone.UTC), "", "", "", "",
				"", "", "", rootAuthSession, null, "");
		sendEvent(event);
	}

	public static void registOidcAuthCodeRedirectEvent(RootAuthSession rootAuthSession, OAuth2Code oauth2Code)
	{
		SyncEvent event = new SyncEvent(EVENT_OIDC_AUTHCODE_REDIRECT, System.currentTimeMillis(), "", "none", "", new DateTime(DateTimeZone.UTC), "",
				"", "", "", "", "", "", rootAuthSession, oauth2Code, "");
		sendEvent(event);
	}

	public static void registOidcTokenGenerateEvent(RootAuthSession rootAuthSession, OAuth2Code oauth2Code)
	{
		SyncEvent event = new SyncEvent(EVENT_OIDC_TOKEN_GENERATE, System.currentTimeMillis(), "", "none", "", new DateTime(DateTimeZone.UTC), "", "",
				"", "", "", "", "", rootAuthSession, oauth2Code, "");
		sendEvent(event);
	}

	public static void registOidcTokenRefreshEvent(RootAuthSession rootAuthSession)
	{
		SyncEvent event = new SyncEvent(EVENT_OIDC_TOKEN_REFRESH, System.currentTimeMillis(), "", "none", "", new DateTime(DateTimeZone.UTC), "", "",
				"", "", "", "", "", rootAuthSession, null, "");
		sendEvent(event);
	}

	public static void registOidcLogoutEvent(String rootAuthSessionId)
	{
		SyncEvent event = new SyncEvent(EVENT_OIDC_LOGOUT, System.currentTimeMillis(), "", "none", "", new DateTime(DateTimeZone.UTC), "", "", "", "",
				"", "", "", null, null, rootAuthSessionId);
		sendEvent(event);
	}

	public static void requestRootAuthSessionEvent(String rootAuthSessionId)
	{
		SyncEvent event = new SyncEvent(EVENT_REQ_OIDC_AUTHN, System.currentTimeMillis(), "", "none", "", new DateTime(DateTimeZone.UTC), "", "", "",
				"", "", "", "", null, null, rootAuthSessionId);
		sendEvent(event);
	}

	public static void reloadOidcClientEvent()
	{
		SyncEvent event = new SyncEvent(EVENT_OIDC_CLIENT_RELOAD, System.currentTimeMillis(), "", "none", "", new DateTime(DateTimeZone.UTC), "", "",
				"", "", "", "", "", null, null, "");
		sendEvent(event);
	}
}