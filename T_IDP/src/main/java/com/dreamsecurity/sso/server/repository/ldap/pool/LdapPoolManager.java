package com.dreamsecurity.sso.server.repository.ldap.pool;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;

public class LdapPoolManager
{
	private static Logger log = LoggerFactory.getLogger(LdapPoolManager.class);

	private static LdapPoolManager instance = null;

	private Map<String, LdapPool> poolMap = new HashMap<String, LdapPool>();

	private LdapPoolManager()
	{
	}

	public static LdapPoolManager getInstance()
	{
		if (instance == null) {
			synchronized (LdapPoolManager.class) {
				if (instance == null) {
					try {
						instance = new LdapPoolManager();
					}
					catch (Exception e) {
						e.printStackTrace();
					}
				}
			}
		}

		return instance;
	}

	public LdapPool getPool(String poolName)
	{
		LdapPool pool = null;

		if (poolMap != null) {
			pool = poolMap.get(poolName);
		}

		return pool;
	}

	public void addPool(String poolName, LdapPool pool)
	{
		if (poolMap != null && !poolMap.containsKey(poolName) && !poolMap.containsValue(pool)) {
			poolMap.put(poolName, pool);

			try {
				log.info("### Ldap Active   count: {}", pool.getNumActive());
				log.info("### Ldap Min Idle count: {}", pool.getMinIdle());

				if (pool.getMinIdle() > pool.getNumActive()) {
					for (int i = 0, limit = pool.getMinIdle() - pool.getNumActive(); i < limit; i++) {
						pool.addObject();
					}
				}
			}
			catch (Exception e) {
				log.error("### LdapPoolManager addPool Exception: {}", e.getMessage());
				throw new RuntimeException(e);
			}
		}
	}

	public Map<String, LdapPool> getPoolMap()
	{
		return poolMap;
	}

	public void setPoolMap(Map<String, LdapPool> poolMap)
	{
		this.poolMap = poolMap;
	}

	public Iterator<String> iterator()
	{
		return poolMap.keySet().iterator();
	}

	public void destroyPool(String poolName) throws Exception
	{
		LdapPool pool = poolMap.get(poolName);

		if (pool != null) {
			pool.close();
		}
	}

	public void destroyPools() throws Exception
	{
		for (Iterator<String> iterator = iterator(); iterator.hasNext();) {
			poolMap.get(iterator.next()).close();
		}

		poolMap.clear();
		poolMap = new HashMap<String, LdapPool>();
	}
}