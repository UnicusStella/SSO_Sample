package com.dreamsecurity.sso.agent.config;

import java.io.File;

import javax.servlet.ServletContext;

import com.dreamsecurity.sso.agent.crypto.CryptoApi;
import com.dreamsecurity.sso.agent.crypto.CryptoApiFactory;
import com.dreamsecurity.sso.agent.util.Util;
import com.dreamsecurity.sso.lib.ccf.CompositeConfiguration;
import com.dreamsecurity.sso.lib.ccf.DefaultConfigurationBuilder;

public class SSOConfig extends CompositeConfiguration
{
	private static SSOConfig instance = null;

	private static String systemHomePath = "dreamsecurity.saml.path";
	private static String configFile = "config/application.xml";
	private static String rootPath;
	private static String homePath;

	public static final String P_SERVER_NAME = "server.name";
	public static final String P_SERVER_CODE = "server.code";
	public static final String P_SERVER_BLOCK = "server.block";

	public static final String P_CERT_KEYPATH = "cert.keypath";
	public static final String P_CERT_KEYCODE = "cert.keycode";
	public static final String P_CERT_SIGNPATH = "cert.signpath";
	public static final String P_CERT_SIGNCODE = "cert.signcode";

	public static final String P_SERVER_APPLCODE = "server.applcode";
	public static final String P_SERVER_SESSIONIDKEY = "server.sessionidkey";

	public static final String P_CRYPTO_TYPE = "crypto.type";
	public static final String P_CRYPTO_CLASS = "crypto.class";

	public static final String P_SSO_HOMEPATH = "sso.homepath";
	public static final String P_METADATA_PATH = "metadata.path";

	public static final String P_INTEGRITY_VERIFY = "integrity.verify";
	public static final String P_CHALLENGE_VERIFY = "challenge.verify";
	public static final String P_AUDITLOG_SEND = "auditlog.send";

	public static final String P_CLIENTIP_METHOD = "clientip.method";
	public static final String P_REQUEST_TIMEOUT = "request.timeout";
	public static final String P_SESSION_SLO = "session.slo";
	public static final String P_SAML_ID = "saml.id";
	public static final String P_CSRFTOKENTIME_LOGIN = "CSRFTokentime.login";
	public static final String P_CHECK_DUPLOGIN_URL = "check.duploggin.url";

	public static final String P_LOG_VERBOSE = "verbose.syscon.use";

	private String serverIP;

	private int authStatus = -1;           // 0: OK, 1: Crypto, 2: SSO
	private boolean distCryptoKey = true;  // true: write audit
	private boolean ssoInitialize = false;

	private SSOConfig()
	{
		try {
			String configFilePath = getHomePath(configFile);
			System.out.println("### SSO Config: " + configFilePath);

			DefaultConfigurationBuilder configBuilder = new DefaultConfigurationBuilder();
			configBuilder.setFile(new File(configFilePath));
			configBuilder.setThrowExceptionOnMissing(false);

			addConfiguration(configBuilder.getConfiguration());

			serverIP = Util.getServerIP();
		}
		catch (Throwable e) {
			e.printStackTrace();
		}
	}

	public static SSOConfig getInstance()
	{
		if (instance == null) {
			synchronized (SSOConfig.class) {
				if (instance == null) {
					try {
						instance = new SSOConfig();
					}
					catch (Exception e) {
						e.printStackTrace();
					}
				}
			}
		}

		return instance;
	}

	public void reload()
	{
		try {
			clear();

			String configFilePath = getHomePath(configFile);
			System.out.println("### SSO Config: " + configFilePath);

			DefaultConfigurationBuilder configBuilder = new DefaultConfigurationBuilder();
			configBuilder.setFile(new File(configFilePath));
			configBuilder.setThrowExceptionOnMissing(false);

			addConfiguration(configBuilder.getConfiguration());
		}
		catch (Throwable e) {
			e.printStackTrace();
		}
	}

	public int getAuthStatus()
	{
		return this.authStatus;
	}

	public void setAuthStatus(int status)
	{
		this.authStatus = status;
	}

	public boolean isDistCryptoKey()
	{
		return this.distCryptoKey;
	}

	public void setDistCryptoKey(boolean distCryptoKey)
	{
		this.distCryptoKey = distCryptoKey;
	}

	public boolean isSsoInitialize()
	{
		return this.ssoInitialize;
	}

	public void setSsoInitialize(boolean ssoInitialize)
	{
		this.ssoInitialize = ssoInitialize;
	}

	public static void setHomeDir(ServletContext servlet, String homedir)
	{
		if (instance != null) {
			return;
		}

		if (servlet == null) {
			return;
		}

		rootPath = servlet.getRealPath("");

		if (Util.isEmpty(System.getProperty(systemHomePath))) {
			homePath = servlet.getRealPath(homedir);
		}
		else {
			homePath = System.getProperty(systemHomePath);
		}

		getInstance();
	}

	public static void setHomeDir(String rootdir, String homedir)
	{
		if (instance != null) {
			return;
		}

		if (Util.isEmpty(rootdir)) {
			return;
		}

		rootPath = rootdir;

		if (Util.isEmpty(System.getProperty(systemHomePath))) {
			homePath = homedir;
		}
		else {
			homePath = System.getProperty(systemHomePath);
		}

		getInstance();
	}

	public static void setHomeDir(String homedir)
	{
		if (instance != null) {
			return;
		}

		if (Util.isEmpty(System.getProperty(systemHomePath))) {
			homePath = homedir;
		}
		else {
			homePath = System.getProperty(systemHomePath);
		}

		getInstance();
	}

	public String getRootPath()
	{
		return rootPath;
	}

	public String getHomePath()
	{
		if (!Util.isEmpty(homePath)) {
			return homePath;
		}

		homePath = System.getProperty(systemHomePath);

		if (!Util.isEmpty(homePath)) {
			return homePath;
		}

		return rootPath + File.separator + "/WEB-INF/dreamsso";
	}

	public String getHomePath(String str)
	{
		String path = getHomePath();

		if (Util.isEmpty(path)) {
			return null;
		}

		return path + File.separator + str;
	}

	public int getIndexOfProperty(String propertyName, String attributeName, String attributeValue)
	{
		return getInstance().getList(new StringBuffer(propertyName).append("[@").append(attributeName).append("]").toString()).indexOf(attributeValue);
	}

	public String getServerName()
	{
		return getInstance().getString(P_SERVER_NAME, "");
	}

	public String getServerIP()
	{
		return serverIP;
	}

	public String getServerCode()
	{
		return getInstance().getString(P_SERVER_CODE, "");
	}

	public String getServerBlock()
	{
		return getInstance().getString(P_SERVER_BLOCK, "");
	}

	public String getCertKeypath()
	{
		return "cert/" + getServerName() + "_Enc.key";
	}

	public String getCertKeycode()
	{
		return getStringProperty(P_CERT_KEYCODE, "");
	}

	public String getCertSignpath()
	{
		return "cert/" + getServerName() + "_Sig.key";
	}

	public String getCertSigncode()
	{
		return getStringProperty(P_CERT_SIGNCODE, "");
	}

	public String getServerApplcode()
	{
		return getInstance().getString(P_SERVER_APPLCODE, "APPLDEFAULT");
	}

	public String getServerSessionidkey()
	{
		return getInstance().getString(P_SERVER_SESSIONIDKEY, "JSESSIONID");
	}

	public String getCryptoType()
	{
		return getInstance().getString(P_CRYPTO_TYPE, "");
	}

	public String getCryptoClass()
	{
		return getInstance().getString(P_CRYPTO_CLASS, "");
	}

	public String getSsoPath()
	{
		return getStringProperty(P_SSO_HOMEPATH, "/sso");
	}

	public String getSsoHomepath()
	{
		return rootPath + getStringProperty(P_SSO_HOMEPATH, "/sso");
	}

	public String getMetadataPath()
	{
		return getInstance().getString(P_METADATA_PATH, "config/metadata.xml");
	}

	public boolean isIntegrityVerify()
	{
		return getInstance().getBoolean(P_INTEGRITY_VERIFY, false);
	}

	public boolean isChallengeVerify()
	{
		return getInstance().getBoolean(P_CHALLENGE_VERIFY, false);
	}

	public boolean isAuditLogSend()
	{
		return getInstance().getBoolean(P_AUDITLOG_SEND, false);
	}

	public String getClientIPMethod()
	{
		return getInstance().getString(P_CLIENTIP_METHOD, "RemoteAddr");
	}

	public String getCheckDupLoginUrl()
	{
		return getInstance().getString(P_CHECK_DUPLOGIN_URL, "");
	}

	public int getRequestTimeout()
	{
		return getInstance().getInt(P_REQUEST_TIMEOUT, 5);
	}

	public boolean getSessionSLO()
	{
		return getInstance().getBoolean(P_SESSION_SLO, true);
	}

	public boolean isSamlId()
	{
		return getInstance().getBoolean(P_SAML_ID, false);
	}

	public int getLoginCSRFTokenTime()
	{
		return getInstance().getInt(P_CSRFTOKENTIME_LOGIN, 1);  // min
	}

	public boolean isVerbose()
	{
		return getInstance().getBoolean(P_LOG_VERBOSE, false);
	}

	public String getStringProperty(String key, String defalut)
	{
		String val = getInstance().getString(key, defalut);

		if (!val.equals(defalut)) {
			val = decryptValue(val);
		}

		return val;
	}

	public Integer getIntegerProperty(String key, int defalut)
	{
		String val = getInstance().getString(key, String.valueOf(defalut));

		if (!val.equals(String.valueOf(defalut))) {
			val = decryptValue(val);
		}

		return Integer.parseInt(val);
	}

	public boolean getBoolenProperty(String key, boolean defalut)
	{
		String val = getInstance().getString(key, String.valueOf(defalut));

		if (!val.equals(String.valueOf(defalut))) {
			val = decryptValue(val);
		}

		return Boolean.valueOf(val);
	}

	private String decryptValue(String input)
	{
		try {
			CryptoApi crypto = CryptoApiFactory.getCryptoApi();
			return crypto.decryptByDEK(input);
		}
		catch (Exception e) {
			e.printStackTrace();
		}

		return "";
	}

	public static String getTOE()
	{
		return "Magic SSO V4.0";
	}

	public static String getDetailVersion()
	{
		return "v4.0.0.3";
	}

	public static String getElementVersion()
	{
		return "Magic SSO V4.0 Agent v4.0.0.3";
	}

	public static String getJarVersion()
	{
		return "magicsso-agent-4.0.0.3";
	}

	public static String getBuildVersion()
	{
		return "20230102";
	}

	public void destroy()
	{
		System.out.println("### destroy");
	}

//	public static void main(String[] args) throws Exception
//	{
//		SSOConfig.setHomeDir("D:/workcc/sp/SP1_CC/WebContent/dreamsso");
//
//		SSOConfig.getInstance().addPropertyDirect("aa.bb", "111");
//		XMLConfiguration conf = (XMLConfiguration) SSOConfig.getInstance().getConfiguration(0);
//		//conf.save("D:/workcc/sp/SP1_CC/WebContent/dreamsso/config/application/sp.xml");
//		conf.save();
//
//		System.out.println("idp.mode : [" + SSOConfig.getInstance().getString("mode", "dev") + "]");
//		System.out.println("idp.admin-console[@enable] : " + SSOConfig.getInstance().getBoolean("admin-console[@enable]"));
//		System.out.println("etc.function.smart.check-interval : " + SSOConfig.getInstance().getInt("function.smart.check-interva", 0));
//
//		try {
//			XMLConfiguration config = new XMLConfiguration("D:/workcc/sp/SP1_CC/WebContent/dreamsso/config/application/sp.xml");
//			config.setThrowExceptionOnMissing(false);
//			config.addProperty("aa.bb", "bb_newValue");
//			config.addProperty("aa.cc", "cc_newValue");
//			//config.clearTree("aa");
//			//config.clearProperty("aa.bb");
//			config.save();
//		}
//		catch (Exception e) {
//			e.printStackTrace();
//		}
//	}
}