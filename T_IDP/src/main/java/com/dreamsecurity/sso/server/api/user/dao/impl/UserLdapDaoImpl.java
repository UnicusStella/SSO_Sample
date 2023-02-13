package com.dreamsecurity.sso.server.api.user.dao.impl;

import java.sql.SQLException;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

import com.dreamsecurity.sso.server.api.user.dao.UserDao;
import com.dreamsecurity.sso.server.repository.ldap.dao.LdapDaoBase;
import com.dreamsecurity.sso.server.util.Util;

public class UserLdapDaoImpl extends LdapDaoBase implements UserDao
{
	public UserLdapDaoImpl()
	{
		super();
	}

	@SuppressWarnings("unchecked")
	public Map<String,String> getStatus() throws SQLException
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("code", "URPY0001");

		return (Map<String,String>) super.selectOneData("user.getPolicy", paramMap);
	}

	@SuppressWarnings("unchecked")
	public Map<String,String> getUserByID(Map<String, String> paramMap) throws SQLException
	{
		Map<String,String> userMap = (Map<String,String>) super.selectOneData("user.getUserByID", paramMap);

		if (userMap.size() > 1) {
			paramMap.put("code", userMap.get("POLICY_CODE"));

			userMap.putAll((Map<String,String>) super.selectOneData("user.getPolicy", paramMap));

			String curTime = Util.getDateFormat("yyyyMMddHHmmssSSS");
			long diffDays = Util.diffDays(userMap.get("PW_UPDATE_TIME").substring(0, 8), "yyyyMMdd");

			userMap.put("TIMESTAM_", curTime);
			userMap.put("NOT_AFTER", Util.addDate(curTime.substring(0, 14), "yyyyMMddHHmmss", Calendar.HOUR, 1));
			userMap.put("PW_UPDATE_DAYS", Long.toString(diffDays));
		}

		return userMap;
	}

	@SuppressWarnings("unchecked")
	public Map<String,String> getUserByCert(Map<String, String> paramMap) throws SQLException
	{
		Map<String,String> userMap = (Map<String,String>) super.selectOneData("user.getUserByCert", paramMap);

		if (userMap.size() > 1) {
			paramMap.put("code", userMap.get("POLICY_CODE"));

			userMap.putAll((Map<String,String>) super.selectOneData("user.getPolicy", paramMap));

			String curTime = Util.getDateFormat("yyyyMMddHHmmssSSS");
			long diffDays = Util.diffDays(userMap.get("PW_UPDATE_TIME").substring(0, 8), "yyyyMMdd");

			userMap.put("TIMESTAM_", curTime);
			userMap.put("NOT_AFTER", Util.addDate(curTime.substring(0, 14), "yyyyMMddHHmmss", Calendar.HOUR, 1));
			userMap.put("PW_UPDATE_DAYS", Long.toString(diffDays));
		}

		return userMap;
	}

	public void setPWMismatchCount(String userId, String count, String status) throws SQLException
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("userId", userId);
		paramMap.put("count", count);
		paramMap.put("status", status);
		paramMap.put("access", Util.getDateFormat("yyyyMMddHHmmss"));

		super.modifyData("user.setPWMismatchCount", paramMap);
	}

	public void setUserAccessInfo(String userId, String userIp, String userBr) throws SQLException
	{
		String curTime = Util.getDateFormat("yyyyMMddHHmmss");

		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("userId", userId);
		paramMap.put("userIp", userIp);
		paramMap.put("userBr", userBr);
		paramMap.put("count", "0");
		paramMap.put("status", "C");
		paramMap.put("access", curTime);

		super.modifyData("user.setUserAccessInfo", paramMap);
	}

	public void setAccessLog(Map<String, String> paramMap) throws SQLException
	{
	}

	@SuppressWarnings("unchecked")
	public void clearLoginIP(String userId, String userIp, String userBr) throws SQLException
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("userId", userId);

		Map<String,String> userMap = (Map<String,String>) super.selectOneData("user.getUserByID", paramMap);

		if (userMap.size() > 1) {
			if (userIp.equals(userMap.get("NOW_LOGIN_IP")) && userBr.equals(userMap.get("NOW_LOGIN_BR"))) {
				paramMap.put("userIp", userIp);
				paramMap.put("userBr", userBr);
				paramMap.put("access", Util.getDateFormat("yyyyMMddHHmmss"));

				super.modifyData("user.clearLoginIP", paramMap);
			}
		}
	}

	public void clearIpInfo(String userId, String userIp, String userBr) throws SQLException
	{
	}

	@SuppressWarnings("unchecked")
	public int setUserPwd(Map<String, String> paramMap) throws SQLException
	{
		Map<String,String> userMap = (Map<String,String>) super.selectOneData("user.getUserByID", paramMap);

		if (userMap.size() > 1) {
			if (Util.isEmpty(paramMap.get("curPwd")) || paramMap.get("curPwd").equals(userMap.get("USER_PASSWORD"))) {
				super.modifyData("user.setUserPwd", paramMap);
				return 1;
			}
		}

		return 0;
	}

	@SuppressWarnings("unchecked")
	public void setAccessTime(String userId, String userIp) throws SQLException
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("userId", userId);

		Map<String,String> userMap = (Map<String,String>) super.selectOneData("user.getUserByID", paramMap);

		if (userMap.size() > 1) {
			if (userIp.equals(userMap.get("NOW_LOGIN_IP"))) {
				paramMap.put("access", Util.getDateFormat("yyyyMMddHHmmss"));

				super.modifyData("user.setAccessTime", paramMap);
			}
		}
	}

	@SuppressWarnings("unchecked")
	public int setUserUnlock(Map<String, String> paramMap) throws SQLException
	{
		Map<String,String> userMap = (Map<String,String>) super.selectOneData("user.getUserByID", paramMap);

		if (userMap.size() > 1) {
			paramMap.put("count", "0");
			paramMap.put("status", "C");

			super.modifyData("user.setUserUnlock", paramMap);
			return 1;
		}

		return 0;
	}

	public Map<String,String> getCSLoginTime(String userId) throws SQLException
	{
		return null;
	}

	public void setCSLoginTime(String userId) throws SQLException
	{
	}

	public void clearCSLoginTime(String userId, String userIp) throws SQLException
	{
	}
	public Map<String, String> getOidcUserInfo(Map<String, Object> paramMap) throws SQLException
	{
		return null;
	}
}