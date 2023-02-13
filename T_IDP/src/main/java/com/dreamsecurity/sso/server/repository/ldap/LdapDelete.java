package com.dreamsecurity.sso.server.repository.ldap;

public class LdapDelete extends LdapQuery
{
	private boolean isCascade;

	public boolean isCascade()
	{
		return isCascade;
	}

	public void setCascade(boolean isCascade)
	{
		this.isCascade = isCascade;
	}

	public String toString()
	{
		StringBuffer info = new StringBuffer(super.toString()).append("CASCADE : ").append(isCascade).append("\n");

		return info.toString();
	}
}