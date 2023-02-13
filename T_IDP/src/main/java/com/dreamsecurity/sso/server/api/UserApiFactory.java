package com.dreamsecurity.sso.server.api;

import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;

import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.exception.SSOException;
import com.dreamsecurity.sso.server.util.Util;

public class UserApiFactory
{
	private static Logger log = LoggerFactory.getLogger(UserApiFactory.class);

	public static UserApi getUserApi() throws SSOException
	{
		SSOConfig config = SSOConfig.getInstance();
		String className = config.getString("userapi.class", "");

		if (Util.isEmpty(className)) {
			className = "com.dreamsecurity.sso.server.api.user.UserController";
		}

		//log.debug("### UserApi Class: {}", className);

		try {
			Class<?> cls = Class.forName(className);
			return (UserApi) cls.newInstance();
		}
		catch (Exception e) {
			log.error("### getUserApi() Exception: {}", e.getMessage());
		}

		return null;
	}
}