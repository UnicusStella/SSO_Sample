package com.dreamsecurity.sso.agent.crypto;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.LinkedList;

import com.dreamsecurity.sso.agent.api.AuditVO;
import com.dreamsecurity.sso.agent.config.SSOConfig;
import com.dreamsecurity.sso.agent.log.Logger;
import com.dreamsecurity.sso.agent.log.LoggerFactory;
import com.dreamsecurity.sso.agent.util.Util;

public class CryptoApiFactory
{
	private static Logger log = LoggerFactory.getInstance().getLogger(CryptoApiFactory.class);

	private static CryptoApi instance = null;

	public static final String CRYPTO_MJC = "MJC";
	public static final String CRYPTO_JCAOS = "JCAOS";

	public static final String CLASS_MJC = "com.dreamsecurity.sso.agent.crypto.api.MJCryptoApi";
	public static final String CLASS_JCAOS = "com.dreamsecurity.sso.agent.crypto.api.JCAOSCryptoApi";

	private static String cryptoType = CRYPTO_MJC;
	private static String cryptoClass = CLASS_MJC;

	private static LinkedList<AuditVO> auditList = new LinkedList<AuditVO>();

	private CryptoApiFactory()
	{
	}

	public static CryptoApi getCryptoApi() throws CryptoApiException
	{
		if (instance != null) {
			if (instance.getStatus() == -1) {
				log.error("### CryptoAPI Status(1) = " + instance.getStatus());
				throw new CryptoApiException("CryptoAPI Status Invalid.");
			}

			return instance;
		}

		SSOConfig config = SSOConfig.getInstance();
		cryptoType = config.getCryptoType();
		cryptoClass = config.getCryptoClass();

		if (Util.isEmpty(cryptoType) || Util.isEmpty(cryptoClass)) {
			cryptoType = CRYPTO_JCAOS;
			cryptoClass = CLASS_JCAOS;
		}

		log.debug("### CryptoAPI class : " + cryptoClass);

		try {
			Class<?> cls = Class.forName(cryptoClass);
			CryptoApi cryptoApi = (CryptoApi) cls.newInstance();

			int result = cryptoApi.init(auditList);

			if (result == 0) {
				config.setAuthStatus(0);
			}
			else {
				config.setAuthStatus(1);

				log.error("### CryptoAPI.init() Result = " + result);

				// 암호모듈 초기화 실패 시 Tomcat 구동 종료
				//shutdownTomcatProcess();

				throw new CryptoApiException("CryptoApi Initialization Failed.");
			}

			instance = cryptoApi;
			return instance;
		}
		catch (Exception e) {
			log.error("### getCryptoApi() Exception : " + e.toString());
			e.printStackTrace();
		}

		return null;
	}

	public static void setInitCryptoAuditInfo()
	{
		for (int i = 0; i < auditList.size(); i++) {
			AuditVO audit = auditList.get(i);
			Util.setAuditInfo(audit.getDate(), audit.getTime(), audit.getUser(), audit.getType(), audit.getResult(),
					audit.getDetail());
		}
	}

	public static void shutdownTomcatProcess()
	{
		try {
			String OS = System.getProperty("os.name").toLowerCase();

			if (OS.indexOf("win") >= 0) {
				return;
			}
			else {
				Process ps = new ProcessBuilder("/bin/sh", "-c", "ps -ef | grep tomcat | grep dreamsso.conf | grep -v grep | awk '{print $2}'").start();
				BufferedReader stdOut = new BufferedReader(new InputStreamReader(ps.getInputStream()));
				String readline = stdOut.readLine();
				//log.debug("### Magic SSO Server PID [" + readline + "]");

				if (!Util.isEmpty(readline)) {
					log.error("### Magic SSO Agent Password Mismatch.");
					log.error("### Tomcat Start aborted.");

					StringBuffer sb = new StringBuffer();
					sb.append("kill -15 ").append(readline);
					//log.debug("### Magic SSO Server Command [" + sb.toString() + "");

					Process kill_ps = new ProcessBuilder("/bin/sh", "-c", sb.toString()).start();

					Thread.sleep(1000);
					kill_ps.destroy();
				}

				ps.destroy();
			}
		}
		catch (Exception e) {
			e.printStackTrace();
			log.error("### Magic SSO Process Kill Exception : " + e.toString());
		}

		return;
	}
}