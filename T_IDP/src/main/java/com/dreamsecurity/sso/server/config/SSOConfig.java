package com.dreamsecurity.sso.server.config;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.ServletContext;

import com.dreamsecurity.sso.lib.ccf.CompositeConfiguration;
import com.dreamsecurity.sso.lib.ccf.DefaultConfigurationBuilder;
import com.dreamsecurity.sso.server.crypto.CryptoApi;
import com.dreamsecurity.sso.server.crypto.CryptoApiFactory;
import com.dreamsecurity.sso.server.util.Util;

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

	public static final String P_CERT_KEYCODE = "cert.keycode";
	public static final String P_CERT_SIGNCODE = "cert.signcode";

	public static final String P_CRYPTO_TYPE = "crypto.type";
	public static final String P_CRYPTO_CLASS = "crypto.class";

	public static final String P_SSO_HOMEPATH = "sso.homepath";
	public static final String P_METADATA_PATH = "metadata.path";

	public static final String P_INTEGRITY_VERIFY = "integrity.verify";
	public static final String P_INTEGRITY_AGENTSEND = "integrity.agentsend";

	public static final String P_CLIENTIP_METHOD = "clientip.method";
	public static final String P_REQUEST_TIMEOUT = "request.timeout";
	public static final String P_DUP_LOGINTYPE = "dup.logintype";
	public static final String P_DUP_ACCESSTIME = "dup.accesstime";
	public static final String P_DUP_BROWSER = "dup.browser";
	public static final String P_DUP_PRELOGIN = "dup.prelogin";
	public static final String P_SERVER_LOGIN = "server.login";
	public static final String P_SSL_USE = "ssl.use";
	public static final String P_SAML_ID = "saml.id";
	public static final String P_CSRFTOKENTIME_LOGIN = "CSRFTokentime.login";
	public static final String P_CSRFTOKENTIME_ADMIN = "CSRFTokentime.admin";

	public static final String PROPERTY_CERT_VERIFY = "cert.verify";
	public static final String PROPERTY_CERT_VERIFY_TYPE = "cert.verify.type";
	public static final String PROPERTY_CERT_VALUE_TYPE = "cert.value.type";

	private String serverIP;

	private int authStatus = -1;  // 0: OK, 1: Crypto, 2: SSO, 3: Process
	private boolean dbCriticalMail = true;  // true: send Mail
	private boolean dbOverflowMail = true;  // true: send Mail

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

	public boolean isDbCriticalMail()
	{
		return this.dbCriticalMail;
	}

	public void setDbCriticalMail(boolean dbCriticalMail)
	{
		this.dbCriticalMail = dbCriticalMail;
	}

	public boolean isDbOverflowMail()
	{
		return this.dbOverflowMail;
	}

	public void setDbOverflowMail(boolean dbOverflowMail)
	{
		this.dbOverflowMail = dbOverflowMail;
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

		return rootPath + File.separator + "/WEB-INF/classes";
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

	public boolean isIntegrityAgentSend()
	{
		return getInstance().getBoolean(P_INTEGRITY_AGENTSEND, false);
	}

	public String getClientIPMethod()
	{
		return getInstance().getString(P_CLIENTIP_METHOD, "RemoteAddr");
	}

	public int getRequestTimeout()
	{
		return getInstance().getInt(P_REQUEST_TIMEOUT, 5);  // min
	}

	public int getDupLoginType()
	{
		return getInstance().getInt(P_DUP_LOGINTYPE, 0);
	}

	public int getDupAccessTime()
	{
		return getInstance().getInt(P_DUP_ACCESSTIME, 5);  // min
	}

	public boolean getDupBrowser()
	{
		return getInstance().getBoolean(P_DUP_BROWSER, false);
	}

	public boolean getDupPreLogin()
	{
		return getInstance().getBoolean(P_DUP_PRELOGIN, false);
	}

	public boolean getServerLogin()
	{
		return getInstance().getBoolean(P_SERVER_LOGIN, false);
	}

	public boolean getSSLUse()
	{
		return getInstance().getBoolean(P_SSL_USE, false);
	}

	public boolean isSamlId()
	{
		return getInstance().getBoolean(P_SAML_ID, false);
	}

	public int getLoginCSRFTokenTime()
	{
		return getInstance().getInt(P_CSRFTOKENTIME_LOGIN, 1);  // min
	}

	public int getAdminCSRFTokenTime()
	{
		return getInstance().getInt(P_CSRFTOKENTIME_ADMIN, 5);  // min
	}

	public boolean getCertVerify()
	{
		return getInstance().getBoolean(PROPERTY_CERT_VERIFY, false);
	}

	public List<Object> getCertVerifyType()
	{
		getInstance().setListDelimiter(',');

		return getInstance().getList(PROPERTY_CERT_VERIFY_TYPE);
	}

	public String getCertValueType()
	{
		return getInstance().getString(PROPERTY_CERT_VALUE_TYPE, "dn");
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

	public ArrayList<String> getListProperty(String key)
	{
		String val = getInstance().getString(key, "");

		if (!val.equals("")) {
			val = decryptValue(val);
		}
		else {
			return null;
		}

		String[] arr = val.split(",");
		ArrayList<String> list = new ArrayList<String>(Arrays.asList(arr));
		return list;
	}

	private String decryptValue(String input)
	{
		try {
			CryptoApi crypto = CryptoApiFactory.getCryptoApi();
			return new String(crypto.decryptByDEK(input));
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
		return "Magic SSO V4.0 Server v4.0.0.3";
	}

	public static String getJarVersion()
	{
		return "magicsso-server-4.0.0.3";
	}

	public static String getBuildVersion()
	{
		return "20230102";
	}

//	public static void main(String[] args) throws Exception
//	{
//		SSOConfig.setHomeDir("D:/workcc/idp/IDP_CC/WebContent/WEB-INF/classes");
//		SSOConfig.getInstance().setThrowExceptionOnMissing(true);
//
//		System.out.println("List : [" + SSOConfig.getInstance().getList("aa") + "]");
//
//		System.out.println("idp.mode : [" + SSOConfig.getInstance().getString("mode", "dev") + "]");
//		System.out.println("idp.admin-console[@enable] : " + SSOConfig.getInstance().getBoolean("admin-console[@enable]"));
//		System.out.println("etc.function.smart.check-interval : " + SSOConfig.getInstance().getInt("function.smart.check-interva", 0));
//
//		if (Boolean.valueOf("true"))
//			System.out.println("### 1. True");
//
//		if (Boolean.valueOf("false"))
//			System.out.println("### 2. True");
//		else
//			System.out.println("### 2. False");
//	}
}