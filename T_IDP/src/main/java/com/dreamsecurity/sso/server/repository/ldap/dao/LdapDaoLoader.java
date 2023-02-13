package com.dreamsecurity.sso.server.repository.ldap.dao;

import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.repository.ldap.LdapQueryExecutor;
import com.dreamsecurity.sso.server.repository.ldap.LdapQueryMapManager;
import com.dreamsecurity.sso.server.repository.ldap.pool.LdapPool;
import com.dreamsecurity.sso.server.repository.ldap.pool.LdapPoolManager;

public class LdapDaoLoader
{
	private static Logger log = LoggerFactory.getLogger(LdapDaoLoader.class);

	public static Object getLdapDao(String daoName, String poolName)
	{
		SSOConfig config = SSOConfig.getInstance();
		int idx = config.getIndexOfProperty("query-map.ldap", "name", poolName);

		String rulefile = config.getString("query-map.ldap(" + idx + ").digester-rule-file");
		String configfile = config.getString("query-map.ldap(" + idx + ").config-file");

		Object dao = null;
		String daoClassPath = null;
		LdapPool ldapPool = LdapPoolManager.getInstance().getPool(poolName);

		if (ldapPool == null) {
			String message = poolName + " can not find.";
			log.error("### {}", message);
			throw new RuntimeException(message);
		}

		LdapQueryMapManager.loadQueryMap(rulefile, configfile);

		try {
			daoClassPath = config.getString("dao." + daoName + ".ldap.class");
			dao = Class.forName(daoClassPath).newInstance();

			((LdapDaoBase) dao).setLdapQueryExecutor(new LdapQueryExecutor(poolName));
		}
		catch (Exception e) {
			log.error("### LdapDaoLoader getLdapDao() Exception: {}", e.getMessage());
			throw new RuntimeException(e);
		}

		log.info("### {} created.", dao.getClass().getName());

		return dao;
	}
}