package com.dreamsecurity.sso.server.api.user.dao;

import java.sql.SQLException;
import java.util.Map;

public interface UserDao
{
	public Map<String,String> getStatus() throws SQLException;

	public Map<String,String> getUserByID(Map<String, String> paramMap) throws SQLException;

	public Map<String,String> getUserByCert(Map<String, String> paramMap) throws SQLException;

	public void setPWMismatchCount(String userId, String count, String status) throws SQLException;

	public void setUserAccessInfo(String userId, String userIp, String userBr) throws SQLException;
	
	public void setAccessLog(Map<String, String> paramMap) throws SQLException;

	public void clearLoginIP(String userId, String userIp, String userBr) throws SQLException;

	public void clearIpInfo(String userId, String userIp, String userBr) throws SQLException;

	public int setUserPwd(Map<String, String> paramMap) throws SQLException;

	public void setAccessTime(String userId, String userIp) throws SQLException;

	public int setUserUnlock(Map<String, String> paramMap) throws SQLException;

	public Map<String,String> getCSLoginTime(String userId) throws SQLException;

	public void setCSLoginTime(String userId) throws SQLException;

	public void clearCSLoginTime(String userId, String userIp) throws SQLException;

	public Map<String, String> getOidcUserInfo(Map<String, Object> paramMap) throws SQLException;
}