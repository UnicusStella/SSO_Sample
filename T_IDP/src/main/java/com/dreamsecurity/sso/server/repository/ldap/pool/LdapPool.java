package com.dreamsecurity.sso.server.repository.ldap.pool;

import com.dreamsecurity.sso.lib.cpl.PoolableObjectFactory;
import com.dreamsecurity.sso.lib.cpl.impl.GenericObjectPool;

public class LdapPool extends GenericObjectPool
{
	private PoolableObjectFactory factory;

	public LdapPool()
	{
		super();
	}

	public LdapPool(PoolableObjectFactory objectFactory)
	{
		super(objectFactory);
	}

	public LdapPool(PoolableObjectFactory objectFactory, int maxActive, byte whenExhaustedAction, long maxWait, int maxIdle, int minIdle,
			boolean testOnBorrow, boolean testOnReturn, long timeBetweenEvictionRunsMillis, int numTestsPerEvictionRun,
			long minEvictableIdleTimeMillis, boolean testWhileIdle, long softMinEvictableIdleTimeMillis, boolean lifo)
	{
		super(objectFactory, maxActive, whenExhaustedAction, maxWait, maxIdle, minIdle, testOnBorrow, testOnReturn, timeBetweenEvictionRunsMillis,
				numTestsPerEvictionRun, minEvictableIdleTimeMillis, testWhileIdle, softMinEvictableIdleTimeMillis, lifo);
	}

	public PoolableObjectFactory getFactory()
	{
		return factory;
	}

	public void setFactory(PoolableObjectFactory factory)
	{
		this.factory = factory;
		super.setFactory(factory);
	}

	public Object getConnection() throws Exception
	{
		return borrowObject();
	}

	public void releaseConnection(Object connection) throws Exception
    {
	    returnObject(connection);
    }

	public void close() throws Exception
	{
		super.close();
	}

	public String getConfiguration()
	{
		StringBuffer info = new StringBuffer("\n<< ").append(this.getClass().getName()).append(" POOL INFO >>\n");
		info.append("POOLABLE OBJECT FACTORY : ").append(getFactory().getClass().getName()).append("\n");
		info.append("LIFO : ").append(getLifo()).append("\n");
		info.append("MAX IDLE : ").append(getMaxIdle()).append("\n");
		info.append("MIN IDLE : ").append(getMinIdle()).append("\n");
		info.append("MAX ACTIVE : ").append(getMaxActive()).append("\n");
		info.append("MAX WAIT : ").append(getMaxWait()).append("\n");
		info.append("WHEN EXHAUSTED ACTION : ").append(getWhenExhaustedAction()).append("\n");
		info.append("TEST ON BORROW : ").append(getTestOnBorrow()).append("\n");
		info.append("TEST ON RETURN : ").append(getTestOnReturn()).append("\n");
		info.append("TEST WHILE IDLE : ").append(getTestWhileIdle()).append("\n");
		info.append("TIME BETWWEN EVICTION RUNS MILLIS : ").append(getTimeBetweenEvictionRunsMillis()).append("\n");
		info.append("NUM TESTS PER EVICTION RUN : ").append(getNumTestsPerEvictionRun()).append("\n");
		info.append("MIN EVICTABLE IDLE TIME MILLIS : ").append(getMinEvictableIdleTimeMillis()).append("\n");
		info.append("CURRENT ACTIVE : " + getNumActive()).append("\n");
		info.append("CURRENT IDLE : " + getNumIdle()).append("\n\n");

		return info.toString();
	}

	public String toString()
	{
		StringBuffer info = new StringBuffer("\n<< ").append(this.getClass().getName()).append(" POOL INFO >>\n");
		info.append("POOLABLE OBJECT FACTORY : ").append(getFactory().getClass().getName()).append("\n");
		info.append("NUM ACTIVE : ").append(getNumActive()).append("\n");
		info.append("NUM IDLE : ").append(getNumIdle()).append("\n");

		return info.toString();
	}
}