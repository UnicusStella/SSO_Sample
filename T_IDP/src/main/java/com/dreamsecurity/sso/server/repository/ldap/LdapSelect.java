package com.dreamsecurity.sso.server.repository.ldap;

import java.util.List;

public class LdapSelect extends LdapQuery
{
	private String resultClass;
	private String filter;
	private String searchScope = "ONE";
	private List sortList;

	public String getResultClass()
	{
		return resultClass;
	}

	public void setResultClass(String resultClass)
	{
		this.resultClass = resultClass;
	}

	public String getFilter()
	{
		return filter;
	}

	public void setFilter(String filter)
	{
		this.filter = filter;
	}

	public String getSearchScope()
	{
		return searchScope;
	}

	public void setSearchScope(String searchScope)
	{
		this.searchScope = searchScope;
	}

	public int getScope()
	{
		int scope = -1;

		if (searchScope != null && !"".equals(searchScope)) {
			if ("BASE".equalsIgnoreCase(searchScope)) {
				scope = SCOPE_BASE;
			}
			else if ("ONE".equalsIgnoreCase(searchScope)) {
				scope = SCOPE_ONE;
			}
			else if ("SUB".equalsIgnoreCase(searchScope)) {
				scope = SCOPE_SUB;
			}
		}

		return scope;
	}

	public List getSortList()
	{
		return sortList;
	}

	public void setSortList(List sortList)
	{
		this.sortList = sortList;
	}

	public void addSort(LdapQueryAttribute attribute)
	{
		sortList.add(attribute);
	}

	public LdapQueryAttribute getSortAttribute(int index)
	{
		return (LdapQueryAttribute) sortList.get(index);
	}

	public String[] getSortAttributeNames()
	{
		String[] attributes = null;

		if (sortList != null && sortList.size() > 0) {
			attributes = new String[sortList.size()];

			for (int i = 0, limit = attributes.length; i < limit; i++) {
				attributes[i] = getSortAttributeName(i);

				if (attributes[i] == null) {
					throw new RuntimeException("Does not exist attribute in result set.\nSort attribute is included in result set");
				}
			}
		}

		return attributes;
	}

	public boolean[] getSortAscendingValues()
	{
		boolean[] ascendings = null;

		if (sortList != null && sortList.size() > 0) {
			ascendings = new boolean[sortList.size()];

			for (int i = 0, limit = ascendings.length; i < limit; i++) {
				LdapQueryAttribute attribute = (LdapQueryAttribute) sortList.get(i);
				ascendings[i] = attribute.isAscending();
			}
		}

		return ascendings;
	}

	public String getSortAttributeName(int index)
	{
		String realName = null;
		String sortAttributeName = ((LdapQueryAttribute) sortList.get(index)).getAttributeName();

		for (int i = 0, limit = attributeList.size(); i < limit; i++) {
			LdapQueryAttribute attribute = (LdapQueryAttribute) attributeList.get(i);

			if (sortAttributeName.equalsIgnoreCase(attribute.getAliasName()) || sortAttributeName.equalsIgnoreCase(attribute.getAttributeName())) {
				realName = attribute.getAttributeName();
				break;
			}
		}

		return realName;
	}

	public boolean isSort()
	{
		boolean sort = false;

		if (sortList != null && sortList.size() > 0) {
			sort = true;
		}

		return sort;
	}

	public String toString()
	{
		StringBuffer info = new StringBuffer("[").append(id).append("]\n");
		info.append("BASE : ").append(base).append("\nFILTER : ").append(filter).append("\nATTRIBUTE : ");
		info.append(attributeList).append("\nSCOPE : ").append(searchScope).append("\n");
		info.append("PARAMETER CLASS : ").append(parameterClass).append("\nRESULT CLASS : ").append(resultClass).append("\n");

		return info.toString();
	}
}