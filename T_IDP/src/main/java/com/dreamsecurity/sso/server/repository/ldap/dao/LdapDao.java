package com.dreamsecurity.sso.server.repository.ldap.dao;

import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.api.admin.dao.impl.AdminLdapDaoImpl;
import com.dreamsecurity.sso.server.api.audit.dao.impl.AuditLdapDaoImpl;
import com.dreamsecurity.sso.server.api.user.dao.impl.UserLdapDaoImpl;
import com.dreamsecurity.sso.server.config.SSOConfig;

public class LdapDao
{
	private static Logger log = LoggerFactory.getLogger(LdapDao.class);

	private static LdapDao instance = null;

	private static AuditLdapDaoImpl auditDao = null;
	private static AdminLdapDaoImpl adminDao = null;
	private static UserLdapDaoImpl userDao = null;

	private static final String poolName = SSOConfig.getInstance().getString("repository.connection-pool.name");

	private LdapDao()
	{
		auditDao = (AuditLdapDaoImpl) LdapDaoLoader.getLdapDao("audit", poolName);
		adminDao = (AdminLdapDaoImpl) LdapDaoLoader.getLdapDao("admin", poolName);
		userDao = (UserLdapDaoImpl) LdapDaoLoader.getLdapDao("user", poolName);
	}

	public static LdapDao getInstance()
	{
		if (instance == null) {
			synchronized (LdapDao.class) {
				if (instance == null) {
					try {
						instance = new LdapDao();
					}
					catch (Exception e) {
						e.printStackTrace();
					}
				}
			}
		}

		return instance;
	}

	public AuditLdapDaoImpl getAuditDao()
	{
		return auditDao;
	}

	public AdminLdapDaoImpl getAdminDao()
	{
		return adminDao;
	}

	public UserLdapDaoImpl getUserDao()
	{
		return userDao;
	}
}