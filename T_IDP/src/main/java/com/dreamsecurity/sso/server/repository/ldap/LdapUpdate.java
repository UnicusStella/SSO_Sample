package com.dreamsecurity.sso.server.repository.ldap;

import netscape.ldap.LDAPModification;

public class LdapUpdate extends LdapQuery
{
	public static final int MODIFICATION_ADD = LDAPModification.ADD;
	public static final int MODIFICATION_REPLACE = LDAPModification.REPLACE;
	public static final int MODIFICATION_DELETE = LDAPModification.DELETE;

	public int getAttributeModificationType(int index)
	{
		int result = -1;
		LdapQueryAttribute attribute = (LdapQueryAttribute) attributeList.get(index);

		if ("ADD".equalsIgnoreCase(attribute.getModificationType())) {
			result = MODIFICATION_ADD;
		}
		else if ("REPLACE".equalsIgnoreCase(attribute.getModificationType())) {
			result = MODIFICATION_REPLACE;
		}
		else if ("DELETE".equalsIgnoreCase(attribute.getModificationType())) {
			result = MODIFICATION_DELETE;
		}

		return result;
	}

	public String getAttributeModificationTypeString(int index)
	{
		return ((LdapQueryAttribute) attributeList.get(index)).getModificationType();
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