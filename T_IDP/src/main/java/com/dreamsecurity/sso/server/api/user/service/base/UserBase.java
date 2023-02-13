package com.dreamsecurity.sso.server.api.user.service.base;

import java.util.HashMap;
import java.util.Map;

import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.api.audit.vo.AccessVO;
import com.dreamsecurity.sso.server.api.service.base.ServiceBase;
import com.dreamsecurity.sso.server.api.user.dao.UserDao;
import com.dreamsecurity.sso.server.api.user.dao.impl.UserDaoImpl;
import com.dreamsecurity.sso.server.api.user.service.crypto.HashCrypto;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.repository.ldap.dao.LdapDao;
import com.dreamsecurity.sso.server.util.Util;

public class UserBase extends ServiceBase
{
	private static Logger log = LoggerFactory.getLogger(UserBase.class);

	protected static HashCrypto hashCrypto = HashCrypto.getInstance();

	public UserDao userDao = null;
	public UserDao userDbDao = null;

	public AccessVO access;

	public static final String FLAG_USER_STATUS_ACTIVE = "C";
	public static final String FLAG_USER_STATUS_LOCKED = "D";
	public static final String FLAG_USER_STATUS_RETIREMENT = "E";

	public static final String FLAG_FUNC_CERT0005 = "_$_CERT0005_SKIP_$_";

	public static final String TYPE_IDPW_LOGIN = "01";
	public static final String TYPE_IDPW_LOGOUT = "11";
	public static final String TYPE_ID_LOGIN = "02";
	public static final String TYPE_ID_LOGOUT = "12";
	public static final String TYPE_CERT_LOGIN = "03";
	public static final String TYPE_CERT_LOGOUT = "13";
	public static final String TYPE_CS_ID_LOGIN = "04";
	public static final String TYPE_CS_ID_LOGOUT = "14";
	public static final String TYPE_CS_CERT_LOGIN = "05";
	public static final String TYPE_CS_CERT_LOGOUT = "15";
	public static final String TYPE_2FA_LOGIN = "98";
	public static final String TYPE_CONNECT_LOGIN = "99";
	public static final String TYPE_LOGIN = "09";
	public static final String TYPE_LOGOUT = "19";

	public static final String TYPE_SUCCESS = "00";

	public static final String TYPE_ERR_LOCK = "AA";
	public static final String TYPE_ERR_RETIRE = "AB";
	public static final String TYPE_ERR_DUP_LOGIN = "AC";
	public static final String TYPE_ERR_PW_MISMATCH = "AD";
	public static final String TYPE_ERR_ID_MISMATCH = "AE";
	public static final String TYPE_ERR_DN_MISMATCH = "AF";

	public UserBase()
	{
		if ("DB".equalsIgnoreCase(repositoryType)) {
			userDao = new UserDaoImpl();
		}
		else {
			userDao = LdapDao.getInstance().getUserDao();

			if (SSOConfig.getInstance().getBoolean("object-pool.dbex(0)[@usable]")) {
				userDbDao = new UserDaoImpl();
			}
		}

		access = new AccessVO();
	}

	protected JSONObject createResult(int code, String message)
	{
		JSONObject result = new JSONObject();
		result.put("code", String.valueOf(code));
		result.put("message", message);
		result.put("data", "");

		writeAccessLog();

		return result;
	}

	protected JSONObject createResult(int code, String message, String data)
	{
		JSONObject result = new JSONObject();
		result.put("code", String.valueOf(code));
		result.put("message", message);
		result.put("data", data);

		writeAccessLog();

		return result;
	}

	public void readyAccessLog(String userId, String userIp, String type, String spName, String browser, String result)
	{
		access.setUserId(userId);
		access.setUserIp(userIp);
		access.setBrowser(browser);
		access.setType(type);
		access.setSpName(spName);
		access.setResult(result);
	}

	public void writeAccessLog()
	{
		try {
			if (Util.isEmpty(access.getUserId())) {
				return;
			}

			if (!access.getResult().equals("00")) {
				log.error("### login failed: user={}, result={}", access.getUserId(), access.getResult());
			}

			Map<String, String> paraMap = new HashMap<String, String>();
			paraMap.put("userId", access.getUserId());
			paraMap.put("userIp", access.getUserIp());
			paraMap.put("browser", access.getBrowser());
			paraMap.put("loginType", access.getType());
			paraMap.put("spName", access.getSpName());
			paraMap.put("result", access.getResult());

			if ("DB".equalsIgnoreCase(repositoryType)) {
				userDao.setAccessLog(paraMap);
			}
			else {
				if (userDbDao != null) {
					userDbDao.setAccessLog(paraMap);
				}
			}
		}
		catch (Exception e) {
			log.error("### writeAccessLog() Exception: {}", e.toString());
		}
	}
}