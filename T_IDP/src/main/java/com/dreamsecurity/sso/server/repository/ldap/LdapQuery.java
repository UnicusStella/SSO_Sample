package com.dreamsecurity.sso.server.repository.ldap;

import java.util.List;

import com.dreamsecurity.sso.server.config.SSOConfig;

public class LdapQuery
{
	public static final int SCOPE_BASE = 0;
	public static final int SCOPE_ONE = 1;
	public static final int SCOPE_SUB = 2;

	public static final int QUERY_SELECT = 0;
	public static final int QUERY_INSERT = 1;
	public static final int QUERY_UPDATE = 2;
	public static final int QUERY_DELETE = 3;

	private static final String rootDn = SSOConfig.getInstance().getString("query-map.ldap.root-dn");

	protected String id;
	protected String parameterClass;
	protected String base;
	protected List attributeList;
	protected boolean isSubstitute = true;

	static
	{
	}

	public String getId()
	{
		return id;
	}

	public void setId(String id)
	{
		this.id = id;
	}

	public String getParameterClass()
	{
		return parameterClass;
	}

	public void setParameterClass(String parameterClass)
	{
		this.parameterClass = parameterClass;
	}

	public String getBase()
	{
		if (base.replaceAll(", ", ",").indexOf(rootDn) < 0) {
			base += "," + rootDn;
		}

		return base;
	}

	public void setBase(String base)
	{
		this.base = base;
	}

	public List getAttributeList()
	{
		return attributeList;
	}

	public String[] getAttributes()
	{
		String[] attributes = null;

		if (attributeList != null && attributeList.size() > 0) {
			attributes = new String[attributeList.size()];

			for (int i = 0, limit = attributes.length; i < limit; i++) {
				attributes[i] = ((LdapQueryAttribute) attributeList.get(i)).getAttributeName();
			}
		}

		return attributes;
	}

	public void setAttributeList(List attributeList)
	{
		this.attributeList = attributeList;
	}

	public void addAttribute(LdapQueryAttribute attribute)
	{
		attributeList.add(attribute);
	}

	public String getAttribute(int index)
	{
		return ((LdapQueryAttribute) attributeList.get(index)).getAttributeName();
	}

	public String getAliasOfAttribute(String attributeName)
	{
		String alias = null;

		for (int i = 0, limit = attributeList.size(); i < limit; i++) {
			LdapQueryAttribute ldapAttribute = (LdapQueryAttribute) attributeList.get(i);

			if (attributeName.equals(ldapAttribute.getAttributeName())) {
				alias = ldapAttribute.getAliasName();
				break;
			}
		}

		if (alias == null || "".equals(alias)) {
			alias = attributeName;
		}

		return alias;
	}

	public String getDefaultValueOfAttribute(String attributeName)
	{
		String defaultValue = null;

		for (int i = 0, limit = attributeList.size(); i < limit; i++) {
			LdapQueryAttribute ldapAttribute = (LdapQueryAttribute) attributeList.get(i);

			if (attributeName.equals(ldapAttribute.getAttributeName())) {
				defaultValue = ldapAttribute.getDefaultValue();
				break;
			}
		}

		return defaultValue;
	}

	public String[] getAttributeValues(int index)
	{
		LdapQueryAttribute attribute = (LdapQueryAttribute) attributeList.get(index);

		return (String[]) attribute.getAttributeValue();
	}

	public String getAttributeValue(int index)
	{
		LdapQueryAttribute attribute = (LdapQueryAttribute) attributeList.get(index);

		return (String) attribute.getAttributeValue()[0];
	}

	public boolean isSubstitute()
	{
		return isSubstitute;
	}

	public void setSubstitute(boolean isSubstitute)
	{
		this.isSubstitute = isSubstitute;
	}

	public String toString()
	{
		StringBuffer info = new StringBuffer("[").append(id).append("]\n");
		info.append("BASE : ").append(base).append("\nATTRIBUTE : ");
		info.append(attributeList).append("\n");
		info.append("PARAMETER CLASS : ").append(parameterClass).append("\n");
		info.append("SUBSTITUTION FLAG : ").append(isSubstitute).append("\n");

		return info.toString();
	}
}