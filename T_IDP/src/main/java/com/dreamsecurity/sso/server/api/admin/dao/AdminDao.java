package com.dreamsecurity.sso.server.api.admin.dao;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.dreamsecurity.sso.server.api.admin.vo.AdminVO;

public interface AdminDao
{
	public Map<String, String> getAdminByID(Map<String, String> paramMap) throws SQLException;

	public List<Object> getAdminIpList() throws SQLException;

	public List<AdminVO> getUsingAdmin() throws SQLException;

	public List<Object> getAdminList() throws SQLException;

	public List<Object> getAdminInfo(Map<String, String> paramMap) throws SQLException;

	public List<Object> getAdpyInfo(Map<String, String> paramMap) throws SQLException;

	public int countUserListByVal(Map<String, String> paramMap) throws SQLException;

	public List<Object> getUserListByVal(Map<String, Object> paramMap) throws SQLException;

	public int getUserRowByVal(Map<String, String> paramMap) throws SQLException;

	public List<Object> getUrpyInfo(Map<String, String> paramMap) throws SQLException;

	public int countUserList() throws SQLException;

	public ArrayList<Object> getUserList(Map<String, Object> paramMap) throws SQLException;

	public int countUserLockedList() throws SQLException;

	public ArrayList<Object> getUserLockedList(Map<String, Object> paramMap) throws SQLException;

	public List<Object> getUserInfo(Map<String, String> paramMap) throws SQLException;

	public int countUserAccessInfo(Map<String, Object> paramMap) throws SQLException;

	public ArrayList<Object> getUserAccessInfo(Map<String, Object> paramMap) throws SQLException;

	public ArrayList<Object> getExcelAccessInfo(Map<String, Object> paramMap) throws SQLException;

	public ArrayList<Object> getStatsDateAccessInfo(Map<String, Object> paramMap) throws SQLException;

	public ArrayList<Object> getStatsMonthAccessInfo(Map<String, Object> paramMap) throws SQLException;

	public ArrayList<Object> getStatsYearAccessInfo(Map<String, Object> paramMap) throws SQLException;

	public void setAdminStatus(Map<String, String> parameterMap) throws SQLException;

	public void setAdminPWMismatchCount(String id, String count, String status) throws SQLException;

	public void setAdminFirstYn(String id) throws SQLException;

	public void setAdminUseYn() throws SQLException;

	public void setAdminAccessInfo(String id, String ip, String br, String tp) throws SQLException;

	public void setAdminLogoutInfo(String id) throws SQLException;

	public int setAdminPwd(Map<String, String> paramMap) throws SQLException;

	public void setAdminInfo(Map<String, String> paramMap) throws SQLException;

	public void removeAdminInfo(Map<String, String> paramMap) throws SQLException;

	public void setAdpyInfo(Map<String, String> paramMap) throws SQLException;

	public void setAdminIp(Map<String, String> paramMap) throws SQLException;

	public void removeAdminIp(Map<String, String> paramMap) throws SQLException;

	public void setUserUnlock(Map<String, String> paramMap) throws SQLException;

	public void setUrpyInfo(Map<String, String> paramMap) throws SQLException;

	public void setUserInfo(Map<String, String> paramMap) throws SQLException;

	public void removeUserInfo(Map<String, String> paramMap) throws SQLException;

	public void setUserChangePwd(Map<String, String> paramMap) throws SQLException;

	// OIDC
	public List<Object> getClientList() throws SQLException;

	public List<Object> getClientRedirect(Map<String, String> paramMap) throws SQLException;

	public List<Object> listClientRedirect(Map<String, String> paramMap) throws SQLException;

	public List<Object> getClientInfo(Map<String, String> paramMap) throws SQLException;

	public List<Object> getClientScope(Map<String, String> paramMap) throws SQLException;
	
	public List<Object> listClientScope(Map<String, String> paramMap) throws SQLException;

	public List<Object> getScopeList() throws SQLException;

	public void removeClient(Map<String, String> paramMap) throws SQLException;

	public void setClientInfo(Map<String, Object> paramMap) throws SQLException;

	public void removeScope(Map<String, String> paramMap) throws SQLException;

	public void setScope(Map<String, Object> paramMap) throws SQLException;

}