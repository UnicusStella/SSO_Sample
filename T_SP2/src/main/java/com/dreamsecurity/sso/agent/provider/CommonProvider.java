package com.dreamsecurity.sso.agent.provider;

import com.dreamsecurity.sso.agent.config.SSOConfig;
import com.dreamsecurity.sso.agent.exception.SSOException;
import com.dreamsecurity.sso.agent.util.Util;

public abstract class CommonProvider
{
	public static final String SESSION_TOKEN = "_TOKEN";

	public static final String SUBJECT_NAME_ID = "__NAME_ID";
	public static final String SUBJECT_EMPTY_ID = "__EMPTY_ID";
	public static final String SUBJECT_LOGIN_CERT = "__LOGIN_CERT";
	public static final String SUBJECT_DUMMY = "dummy";

	public static final String SERVICE_05 = "_$_CERT0005_SKIP_$_";
	public static final String SEPARATOR = "^@^";

	public static final String SESSION_ROLE = "_ROLE";

	protected String serverName;
	protected String serverIP;

	protected CommonProvider() throws SSOException
	{
		this.serverName = SSOConfig.getInstance().getServerName();
		this.serverIP = Util.getServerIP();
	}
}