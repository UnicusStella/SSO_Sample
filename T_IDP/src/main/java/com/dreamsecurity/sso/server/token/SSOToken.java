package com.dreamsecurity.sso.server.token;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.io.Serializable;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import com.dreamsecurity.sso.lib.jsn.JSONObject;

public class SSOToken implements Serializable
{
	private static final long serialVersionUID = 1828754735578848277L;

	public static final String GROUP_NAME_USER = "USER";
	public static final String PROP_NAME_ID = "ID";
	public static final String PROP_NAME_EMPNO = "EMP_NO";
	public static final String PROP_NAME_DEPT_CODE = "DEPT_CODE";
	public static final String PROP_NAME_TIMESTAMP = "TIMESTAMP";
	public static final String PROP_NAME_NOT_AFTER = "NOT_AFTER";
	public static final String PROP_NAME_LAST_CHANGE_PASSWORD_TIME = "LAST_CHANGE_PASSWORD_TIME";
	public static final String PROP_NAME_SSN = "SSN";
	public static final String PROP_NAME_NAME = "NAME";
	public static final String PROP_NAME_DEPT_NAME = "DEPT_NAME";
	public static final String GROUP_NAME_APPLDEFAULT = "APPLDEFAULT";
	public static final String PROP_NAME_TOKEN_VALUE = "TOKEN_VALUE";
	public static final String PROP_NAME_ACL_LIST = "ACL_LIST";
	public static final String PROP_NAME_SITE_NICK = "SITE_NICK";

	Map<String, Object> map = new HashMap<String, Object>();
	Properties entries = new Properties();

	private StringBuilder tokenValue = null;

	public SSOToken()
	{
		super();
	}

	public SSOToken(StringBuilder str) throws IOException
	{
		load(new StringReader(str.toString()));
		tokenValue = str;
	}

	public SSOToken(String str) throws IOException
	{
		load(new StringReader(str));
		tokenValue = new StringBuilder(str);
	}

	public StringBuilder getTokenValue()
	{
		return tokenValue;
	}

	public void load(Reader input) throws IOException
	{
		BufferedReader reader = new BufferedReader(input);

		String line;
		String group = null;
		Properties entry = new Properties();

		while ((line = reader.readLine()) != null) {
			line = line.trim();
			if (line.length() < 1 || line.startsWith("#"))
				continue;

			if (line.startsWith("[")) {
				int position = line.indexOf("]");
				if (position < 0)
					throw new IOException("Invalid Syntex: " + line);

				if (group != null) // ?????? ????????? ?????? ????????????.
					map.put(group, entry);

				group = line.substring(1, position); // ????????? ???????????? ????????????.
				entry = new Properties(); // ????????? ?????? ???????????? ?????????.

				continue;
			}

			int idx = line.indexOf("=");
			if (idx < 0)
				throw new IOException("Invalid Syntex: " + line);

			String name = (line.substring(0, idx)).trim();
			String value = line.substring(idx + 1).trim();
			entries.put(name, value); // ?????? ????????? ????????? ?????? Properties?????? ????????????.
			entry.put(name, value); // ?????? ?????? Proeprties??? ????????????.
		}

		map.put(group, entry); // ???????????? ????????? ????????? ???????????? ?????? ?????????.
	}

	public String getProperty(String name)
	{
		return entries.getProperty(name);
	}

	public String getProperty(String group, String name)
	{
		Properties g = (Properties) map.get(group);

		return g == null ? null : g.getProperty(name);
	}

	public String[] getGroupNames()
	{
		String[] names = new String[map.keySet().size()];
		map.keySet().toArray(names);

		return names;
	}

	public List getPropertyNames()
	{
		ArrayList result = new ArrayList();
		Enumeration enumeration = entries.propertyNames();
		while (enumeration.hasMoreElements()) {
			result.add(enumeration.nextElement());
		}
		return result;
	}

	public List getPropertyNames(String groupName)
	{
		Properties properties = ((Properties) map.get(groupName));
		if (properties == null) {
			return null;
		}
		ArrayList result = new ArrayList();
		Enumeration enumeration = properties.propertyNames();
		while (enumeration.hasMoreElements()) {
			result.add(enumeration.nextElement());
		}
		return result;
	}

	public void setProperty(String group, String name, String value)
	{
		Properties g = (Properties) map.get(group);

		if (g != null) {
			g.setProperty(name, value);
		}
	}

	public String getId()
	{
		return this.getProperty(PROP_NAME_ID);
	}

	public String toString()
	{
		return this.tokenValue.toString();
	}

	public String getAccessAppNameList()
	{
		StringBuffer applNames = new StringBuffer();
		String[] groupNames = this.getGroupNames();
		for (int i = 0; i < groupNames.length; i++) {
			String groupName = groupNames[i];
			if (groupName.startsWith("APPL")) {
				if (applNames.length() > 0)
					applNames.append(",");

				applNames.append(this.getProperty(groupName, PROP_NAME_NAME));
			}
		}
		return applNames.toString();
	}

	public String getAclList()
	{
		return this.getProperty(PROP_NAME_ACL_LIST);
	}

	public String getAccessAppCodeList()
	{
		StringBuffer applCodes = new StringBuffer();
		String[] groupNames = this.getGroupNames();
		for (int i = 0; i < groupNames.length; i++) {
			String groupName = groupNames[i];
			if (groupName.startsWith("APPL")) {
				if (applCodes.length() > 0)
					applCodes.append(",");

				applCodes.append(groupName);
			}
		}
		return applCodes.toString();
	}

	public String toJsonString()
	{
		JSONObject dataJson = new JSONObject();

		String[] groupNames = this.getGroupNames();

		for (int i = 0; i < groupNames.length; i++) {
			JSONObject groupJson = new JSONObject();

			String groupName = groupNames[i];
			Properties entry = (Properties) map.get(groupName);

			if (entry == null) {
				dataJson.put(groupName, groupJson);
				continue;
			}

			Enumeration enm = entry.propertyNames();

			while (enm.hasMoreElements()) {
				String key = (String) enm.nextElement();
				String value = entry.getProperty(key);

				groupJson.put(key, value);
			}

			dataJson.put(groupName, groupJson);
		}

		return dataJson.toString();
	}

	public void finalize() throws Throwable
	{
		for (int i = 0; i < this.tokenValue.length(); i++)
			this.tokenValue.setCharAt(i, '0');
	}
}