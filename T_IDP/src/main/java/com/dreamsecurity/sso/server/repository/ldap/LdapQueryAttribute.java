package com.dreamsecurity.sso.server.repository.ldap;

public class LdapQueryAttribute
{
	private String modificationType = "REPLACE";
	private String attributeName;
	private String[] attributeValue;
	private String aliasName;
	private boolean isAscending = true;
	private String defaultValue = null;

	public String getModificationType()
	{
		return modificationType;
	}

	public void setModificationType(String modificationType)
	{
		this.modificationType = modificationType;
	}

	public String getAttributeName()
	{
		return attributeName;
	}

	public void setAttributeName(String attributeName)
	{
		this.attributeName = attributeName;
	}

	public String[] getAttributeValue()
	{
		return attributeValue;
	}

	public void setAttributeValue(String[] attributeValue)
	{
		this.attributeValue = attributeValue;
	}

	public String getAliasName()
	{
		return aliasName;
	}

	public void setAliasName(String aliasName)
	{
		this.aliasName = aliasName;
	}

	public boolean isAscending()
	{
		return isAscending;
	}

	public void setAscending(boolean isAscending)
	{
		this.isAscending = isAscending;
	}

	public String getDefaultValue()
	{
		return defaultValue;
	}

	public void setDefaultValue(String defaultValue)
	{
		this.defaultValue = defaultValue;
	}

	public String toString()
	{
		StringBuffer info = new StringBuffer("{").append(attributeName).append(", ");
		info.append("MODIFICATION TYPE : ").append(modificationType).append(", ATTRIBUTE VALUE : ");
		info.append(attributeValue).append(", ALIAS : ").append(aliasName).append("}");
		return info.toString();
	}
}