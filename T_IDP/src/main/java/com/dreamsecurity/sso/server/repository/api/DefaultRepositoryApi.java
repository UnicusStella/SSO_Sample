package com.dreamsecurity.sso.server.repository.api;

import com.dreamsecurity.sso.server.exception.SSOException;
import com.dreamsecurity.sso.server.repository.RepositoryApi;
import com.dreamsecurity.sso.server.repository.connection.DBConnectMap;
import com.dreamsecurity.sso.server.repository.ldap.pool.LdapPoolLoader;

public class DefaultRepositoryApi implements RepositoryApi
{
	public void create() throws SSOException
	{
		try {
			createRepositoryPool();
		}
		catch (Throwable t) {
			throw new SSOException(t);
		}

		return;
	}

	public static void createRepositoryPool()
	{
		createRepositoryPool("ldap");

		createRepositoryPool("db");
	}

	private static void createRepositoryPool(String poolType)
	{
		if (poolType.equals("db")) {
			DBConnectMap.getInstance().createDBConnections();
		}
		else {
			LdapPoolLoader.getInstance().createLdapPools();
		}
	}
}