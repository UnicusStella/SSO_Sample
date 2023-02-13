package com.dreamsecurity.sso.server.api.admin.service.base;

import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.server.api.admin.dao.AdminDao;
import com.dreamsecurity.sso.server.api.admin.dao.impl.AdminDaoImpl;
import com.dreamsecurity.sso.server.api.admin.service.crypto.HashCrypto;
import com.dreamsecurity.sso.server.api.audit.vo.AccessVO;
import com.dreamsecurity.sso.server.api.service.base.ServiceBase;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.repository.ldap.dao.LdapDao;

public class AdminBase extends ServiceBase
{
	protected static HashCrypto hashCrypto = HashCrypto.getInstance();

	public AdminDao adminDao = null;
	public AdminDao adminDbDao = null;

	public AccessVO access;

	public static final String FLAG_USER_STATUS_ACTIVE = "C";
	public static final String FLAG_USER_STATUS_LOCKED = "D";
	public static final String FLAG_USER_STATUS_RETIREMENT = "E";

	public AdminBase()
	{
		if ("DB".equalsIgnoreCase(repositoryType)) {
			adminDao = new AdminDaoImpl();
		}
		else {
			adminDao = LdapDao.getInstance().getAdminDao();

			if (SSOConfig.getInstance().getBoolean("object-pool.dbex(0)[@usable]")) {
				adminDbDao = new AdminDaoImpl();
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

		return result;
	}

	protected JSONObject createResult(int code, String message, String data)
	{
		JSONObject result = new JSONObject();
		result.put("code", String.valueOf(code));
		result.put("message", message);
		result.put("data", data);

		return result;
	}
}