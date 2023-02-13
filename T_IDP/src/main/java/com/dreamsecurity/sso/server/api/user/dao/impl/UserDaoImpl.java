package com.dreamsecurity.sso.server.api.user.dao.impl;

import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import com.dreamsecurity.sso.server.api.user.dao.UserDao;
import com.dreamsecurity.sso.server.repository.connection.DBConnectMap;
import com.dreamsecurity.sso.lib.ism.client.SqlMapClient;

public class UserDaoImpl implements UserDao
{
	private SqlMapClient smc = null;

	public UserDaoImpl()
	{
		smc = DBConnectMap.getInstance().getConnection("default_db");
	}

	@SuppressWarnings("unchecked")
	public Map<String,String> getStatus() throws SQLException
	{
		return (Map<String,String>) smc.queryForObject("getStatus");
	}

	@SuppressWarnings("unchecked")
	public Map<String,String> getUserByID(Map<String, String> paramMap) throws SQLException
	{
		return (Map<String,String>) smc.queryForObject("getUserByID", paramMap);
	}

	@SuppressWarnings("unchecked")
	public Map<String,String> getUserByCert(Map<String, String> paramMap) throws SQLException
	{
		return (Map<String,String>) smc.queryForObject("getUserByCert", paramMap);
	}

	public void setPWMismatchCount(String userId, String count, String status) throws SQLException
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("userId", userId);
		paramMap.put("count", count);
		paramMap.put("status", status);

		smc.insert("setPWMismatchCount", paramMap);
	}

	public void setUserAccessInfo(String userId, String userIp, String userBr) throws SQLException
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("userId", userId);
		paramMap.put("userIp", userIp);
		paramMap.put("userBr", userBr);

		smc.update("setUserAccessInfo", paramMap);

		int cnt = smc.update("setIpInfo", paramMap);
		if (cnt == 0) {
			smc.insert("addIpInfo", paramMap);
		}
	}

	public void setAccessLog(Map<String, String> paramMap) throws SQLException
	{
		smc.insert("setAccessLog", paramMap);
	}

	public void clearLoginIP(String userId, String userIp, String userBr) throws SQLException
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("userId", userId);
		paramMap.put("userIp", userIp);
		paramMap.put("userBr", userBr);

		smc.update("clearLoginIP", paramMap);
	}

	public void clearIpInfo(String userId, String userIp, String userBr) throws SQLException
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("userId", userId);
		paramMap.put("userIp", userIp);
		paramMap.put("userBr", userBr);

		smc.update("clearIpInfo", paramMap);
	}

	public int setUserPwd(Map<String, String> paramMap) throws SQLException
	{
		return smc.update("setUserPwd", paramMap);
	}

	public void setAccessTime(String userId, String userIp) throws SQLException
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("userId", userId);
		paramMap.put("userIp", userIp);

		smc.update("setAccessTime", paramMap);
	}

	public int setUserUnlock(Map<String, String> paramMap) throws SQLException
	{
		return smc.update("setUserUnlock", paramMap);
	}

	@SuppressWarnings("unchecked")
	public Map<String,String> getCSLoginTime(String userId) throws SQLException
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("userId", userId);

		return (Map<String,String>) smc.queryForObject("getCSLoginTime", paramMap);
	}

	public void setCSLoginTime(String userId) throws SQLException
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("userId", userId);

		smc.update("setCSLoginTime", paramMap);
	}

	public void clearCSLoginTime(String userId, String userIp) throws SQLException
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("userId", userId);
		paramMap.put("userIp", userIp);

		smc.update("clearCSLoginTime", paramMap);
	}

	@SuppressWarnings("unchecked")
	public Map<String, String> getOidcUserInfo(Map<String, Object> paramMap) throws SQLException
	{
		return (Map<String, String>) smc.queryForObject("getOidcUserInfo", paramMap);
	}
}