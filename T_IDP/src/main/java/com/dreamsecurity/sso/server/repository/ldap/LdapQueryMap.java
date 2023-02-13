package com.dreamsecurity.sso.server.repository.ldap;

import java.util.HashMap;
import java.util.Map;

public class LdapQueryMap
{
	private String id;
	private Map selectMap;
	private Map insertMap;
	private Map updateMap;
	private Map deleteMap;

	public LdapQueryMap()
	{
		selectMap = new HashMap();
		insertMap = new HashMap();
		updateMap = new HashMap();
		deleteMap = new HashMap();
	}

	public String getId()
	{
		return id;
	}

	public void setId(String id)
	{
		this.id = id;
	}

	public void addSelect(LdapSelect select)
	{
		selectMap.put(select.getId(), select);
	}

	public LdapSelect getSelect(String id)
	{
		return (LdapSelect) selectMap.get(id);
	}

	public void addInsert(LdapInsert insert)
	{
		insertMap.put(insert.getId(), insert);
	}

	public LdapInsert getInsert(String id)
	{
		return (LdapInsert) insertMap.get(id);
	}

	public void addUpdate(LdapUpdate update)
	{
		updateMap.put(update.getId(), update);
	}

	public LdapUpdate getUpdate(String id)
	{
		return (LdapUpdate) updateMap.get(id);
	}

	public void addDelete(LdapDelete delete)
	{
		deleteMap.put(delete.getId(), delete);
	}

	public LdapDelete getDelete(String id)
	{
		return (LdapDelete) deleteMap.get(id);
	}

	public String toString()
	{
		StringBuffer info = new StringBuffer("[").append(id).append("]\n");

		if (selectMap.size() > 0) {
			info.append(selectMap);
		}

		if (insertMap.size() > 0) {
			info.append("\n").append(insertMap);
		}

		if (updateMap.size() > 0) {
			info.append("\n").append(updateMap);
		}

		if (deleteMap.size() > 0) {
			info.append("\n").append(deleteMap);
		}

		return info.toString();
	}
}