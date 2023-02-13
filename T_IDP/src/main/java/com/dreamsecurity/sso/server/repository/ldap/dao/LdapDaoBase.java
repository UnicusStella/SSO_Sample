package com.dreamsecurity.sso.server.repository.ldap.dao;

import java.util.List;

import netscape.ldap.LDAPConnection;

import com.dreamsecurity.sso.server.repository.ldap.LdapQueryExecutor;

public class LdapDaoBase
{

	protected LdapQueryExecutor ldapQueryExecutor;

	public LdapDaoBase()
	{
	}

	public LdapQueryExecutor getLdapQueryExecutor()
	{
		return ldapQueryExecutor;
	}

	public void setLdapQueryExecutor(LdapQueryExecutor ldabQueryExecutor)
	{
		this.ldapQueryExecutor = ldabQueryExecutor;
	}

	public Object addData(String queryId, Object parameter)
	{
		ldapQueryExecutor.addData(queryId, parameter);

		return null;
	}

	public int modifyData(String queryId, Object parameter)
	{
		ldapQueryExecutor.modifyData(queryId, parameter);

		return 0;
	}

	public int removeData(String queryId, Object parameter)
	{
		ldapQueryExecutor.deleteData(queryId, parameter);

		return 0;
	}

	public List selectData(String queryId, Object parameter)
	{
		return ldapQueryExecutor.queryForList(queryId, parameter);
	}

	public Object selectOneData(String queryId, Object parameter)
	{
		return ldapQueryExecutor.queryForObject(queryId, parameter);
	}

	public int selectCount(String queryId, Object parameter)
	{
		return ldapQueryExecutor.queryForCount(queryId, parameter);
	}

	// 기존 Cheroky 에서 얻어 온 LDAP Connection을 사용하기 위한 임시 메서드 정의
	public Object addData(String queryId, Object parameter, LDAPConnection ld)
	{
		ldapQueryExecutor.addData(queryId, parameter);

		return null;
	}

	public int modifyData(String queryId, Object parameter, LDAPConnection ld)
	{
		ldapQueryExecutor.modifyData(queryId, parameter);

		return 0;
	}

	public int removeData(String queryId, Object parameter, LDAPConnection ld)
	{
		ldapQueryExecutor.deleteData(queryId, parameter);

		return 0;
	}

	public List selectData(String queryId, Object parameter, LDAPConnection ld)
	{
		return ldapQueryExecutor.queryForList(queryId, parameter);
	}

	public Object selectOneData(String queryId, Object parameter, LDAPConnection ld)
	{
		return ldapQueryExecutor.queryForObject(queryId, parameter);
	}
}