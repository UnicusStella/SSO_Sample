package com.dreamsecurity.sso.server.provider;

import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.util.Util;

public abstract class CommonProvider
{
	public static final String SESSION_SSO_ID = "SSO_ID";
	public static final String SESSION_TOKEN = "_TOKEN";
	public static final String SESSION_TOKEN_EK = "_TEK";
	public static final String SESSION_AUTHCODE = "_AUTHCODE";
	public static final String SESSION_FAIL_SP_APPCODE = "FAIL_SP_APPLCODE";

    public static final String SUBJECT_EMPTY_ID = "__EMPTY_ID";
    public static final String SUBJECT_LOGIN_CERT = "__LOGIN_CERT";

	public static final String SUFFIX_SP_SESSION = "^^^SESS_ID";

	public static final String SERVICE_05 = "_$_CERT0005_SKIP_$_";

	protected String serverName;
	protected String serverIP;

	protected CommonProvider()
	{
		this.serverName = SSOConfig.getInstance().getServerName();
		this.serverIP = Util.getServerIP();
	}
}