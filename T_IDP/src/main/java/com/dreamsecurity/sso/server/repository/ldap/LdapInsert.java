package com.dreamsecurity.sso.server.repository.ldap;

import java.util.List;

public class LdapInsert extends LdapQuery
{
	private List objectClassList = null;

	public List getObjectClassList()
	{
		return objectClassList;
	}

	public void setObjectClassList(List objectClassList)
	{
		this.objectClassList = objectClassList;
	}
}
