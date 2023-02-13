package com.dreamsecurity.sso.server.api.admin.dao.impl;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.dreamsecurity.sso.server.api.admin.dao.AdminDao;
import com.dreamsecurity.sso.server.api.admin.vo.AdminVO;
import com.dreamsecurity.sso.server.repository.connection.DBConnectMap;
import com.dreamsecurity.sso.lib.ism.client.SqlMapClient;

public class AdminDaoImpl implements AdminDao
{
	private SqlMapClient smc = null;

	public AdminDaoImpl()
	{
		smc = DBConnectMap.getInstance().getConnection("default_db");
	}

	@SuppressWarnings("unchecked")
	public Map<String, String> getAdminByID(Map<String, String> paramMap) throws SQLException
	{
		return (Map<String, String>) smc.queryForObject("getAdminByID", paramMap);
	}

	@SuppressWarnings("unchecked")
	public List<Object> getAdminIpList() throws SQLException
	{
		return (List<Object>) smc.queryForList("getAdminIpList");
	}

	@SuppressWarnings("unchecked")
	public List<AdminVO> getUsingAdmin() throws SQLException
	{
		return (List<AdminVO>) smc.queryForList("getUsingAdmin");
	}

	@SuppressWarnings("unchecked")
	public List<Object> getAdminList() throws SQLException
	{
		return (List<Object>) smc.queryForList("getAdminList");
	}

	@SuppressWarnings("unchecked")
	public List<Object> getAdminInfo(Map<String, String> paramMap) throws SQLException
	{
		return (List<Object>) smc.queryForList("getAdminInfo", paramMap);
	}

	@SuppressWarnings("unchecked")
	public List<Object> getAdpyInfo(Map<String, String> paramMap) throws SQLException
	{
		return (List<Object>) smc.queryForList("getAdpyInfo", paramMap);
	}

	@SuppressWarnings("unchecked")
	public int countUserListByVal(Map<String, String> paramMap) throws SQLException
	{
		int cnt = 0;
		Map<String, Object> resultMap = null;

		resultMap = (Map<String, Object>) smc.queryForObject("countUserListByVal", paramMap);

		if (resultMap.size() == 1) {
			String temp = String.valueOf(resultMap.get("CNT"));
			cnt = Integer.parseInt(temp);
		}

		return cnt;
	}

	@SuppressWarnings("unchecked")
	public List<Object> getUserListByVal(Map<String, Object> paramMap) throws SQLException
	{
		return (List<Object>) smc.queryForList("getUserListByVal", paramMap);
	}

	@SuppressWarnings("unchecked")
	public int getUserRowByVal(Map<String, String> paramMap) throws SQLException
	{
		int cnt = 0;
		Map<String, Object> resultMap = null;

		resultMap = (Map<String, Object>) smc.queryForObject("getUserRowByVal", paramMap);

		if (resultMap.size() == 1) {
			String temp = String.valueOf(resultMap.get("NUM"));
			cnt = Integer.parseInt(temp);
		}

		return cnt;
	}

	@SuppressWarnings("unchecked")
	public List<Object> getUrpyInfo(Map<String, String> paramMap) throws SQLException
	{
		return (List<Object>) smc.queryForList("getUrpyInfo", paramMap);
	}

	@SuppressWarnings("unchecked")
	public int countUserList() throws SQLException
	{
		int cnt = 0;
		Map<String, Object> resultMap = null;

		resultMap = (Map<String, Object>) smc.queryForObject("countUserList");

		if (resultMap.size() == 1) {
			String temp = String.valueOf(resultMap.get("CNT"));
			cnt = Integer.parseInt(temp);
		}

		return cnt;
	}

	@SuppressWarnings("unchecked")
	public ArrayList<Object> getUserList(Map<String, Object> paramMap) throws SQLException
	{
		return (ArrayList<Object>) smc.queryForList("getUserList", paramMap);
	}

	@SuppressWarnings("unchecked")
	public int countUserLockedList() throws SQLException
	{
		int cnt = 0;
		Map<String, Object> resultMap = null;

		resultMap = (Map<String, Object>) smc.queryForObject("countUserLockedList");

		if (resultMap.size() == 1) {
			String temp = String.valueOf(resultMap.get("CNT"));
			cnt = Integer.parseInt(temp);
		}

		return cnt;
	}

	@SuppressWarnings("unchecked")
	public ArrayList<Object> getUserLockedList(Map<String, Object> paramMap) throws SQLException
	{
		return (ArrayList<Object>) smc.queryForList("getUserLockedList", paramMap);
	}

	@SuppressWarnings("unchecked")
	public List<Object> getUserInfo(Map<String, String> paramMap) throws SQLException
	{
		return (List<Object>) smc.queryForList("getUserInfo", paramMap);
	}

	@SuppressWarnings("unchecked")
	public int countUserAccessInfo(Map<String, Object> paramMap) throws SQLException
	{
		int cnt = 0;
		Map<String, Object> resultMap = null;

		resultMap = (Map<String, Object>) smc.queryForObject("countUserAccessInfo", paramMap);

		if (resultMap.size() == 1) {
			String temp = String.valueOf(resultMap.get("CNT"));
			cnt = Integer.parseInt(temp);
		}

		return cnt;
	}

	@SuppressWarnings("unchecked")
	public ArrayList<Object> getUserAccessInfo(Map<String, Object> paramMap) throws SQLException
	{
		return (ArrayList<Object>) smc.queryForList("getUserAccessInfo", paramMap);
	}

	@SuppressWarnings("unchecked")
	public ArrayList<Object> getExcelAccessInfo(Map<String, Object> paramMap) throws SQLException
	{
		return (ArrayList<Object>) smc.queryForList("getExcelAccessInfo", paramMap);
	}

	@SuppressWarnings("unchecked")
	public ArrayList<Object> getStatsDateAccessInfo(Map<String, Object> paramMap) throws SQLException
	{
		return (ArrayList<Object>) smc.queryForList("getStatsDateAccessInfo", paramMap);
	}

	@SuppressWarnings("unchecked")
	public ArrayList<Object> getStatsMonthAccessInfo(Map<String, Object> paramMap) throws SQLException
	{
		return (ArrayList<Object>) smc.queryForList("getStatsMonthAccessInfo", paramMap);
	}

	@SuppressWarnings("unchecked")
	public ArrayList<Object> getStatsYearAccessInfo(Map<String, Object> paramMap) throws SQLException
	{
		return (ArrayList<Object>) smc.queryForList("getStatsYearAccessInfo", paramMap);
	}

	public void setAdminStatus(Map<String, String> parameterMap) throws SQLException
	{
		smc.update("setAdminStatus", parameterMap);
	}

	public void setAdminPWMismatchCount(String id, String count, String status) throws SQLException
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("id", id);
		paramMap.put("count", count);
		paramMap.put("status", status);

		smc.insert("setAdminPWMismatchCount", paramMap);
	}

	public void setAdminFirstYn(String id) throws SQLException
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("id", id);

		smc.update("setAdminFirstYn", paramMap);
	}

	public void setAdminUseYn() throws SQLException
	{
		smc.update("setAdminUseYn");
	}

	public void setAdminAccessInfo(String id, String ip, String br, String tp) throws SQLException
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("id", id);
		paramMap.put("ip", ip);
		paramMap.put("br", br);

		if (tp.equals("S")) {
			paramMap.put("use", "Y");

			smc.update("setAdminUseYn");
			smc.update("setAdminLoginInfo", paramMap);
		}
		else {
			paramMap.put("use", "");

			smc.update("setAdminLoginInfo", paramMap);
		}
	}

	public void setAdminLogoutInfo(String id) throws SQLException
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("id", id);

		smc.update("setAdminLogoutInfo", paramMap);
	}

	public int setAdminPwd(Map<String, String> paramMap) throws SQLException
	{
		return smc.update("setAdminPwd", paramMap);
	}

	public void setAdminInfo(Map<String, String> paramMap) throws SQLException
	{
		if (paramMap.get("newflag").equals("1")) {
			smc.insert("createAdmin", paramMap);
		}
		else {
			int cnt = smc.update("setAdmin", paramMap);

			if (cnt == 0)
				smc.insert("createAdmin", paramMap);
		}
	}

	public void removeAdminInfo(Map<String, String> paramMap) throws SQLException
	{
		smc.delete("removeAdmin", paramMap);
	}

	public void setAdpyInfo(Map<String, String> paramMap) throws SQLException
	{
		smc.update("setAdpyInfo", paramMap);
	}

	public void setAdminIp(Map<String, String> paramMap) throws SQLException
	{
		smc.insert("createAdminIp", paramMap);
	}

	public void removeAdminIp(Map<String, String> paramMap) throws SQLException
	{
		smc.delete("removeAdminIp", paramMap);
	}

	public void setUserUnlock(Map<String, String> paramMap) throws SQLException
	{
		smc.update("setUserUnlock", paramMap);
	}

	public void setUrpyInfo(Map<String, String> paramMap) throws SQLException
	{
		smc.update("setUrpyInfo", paramMap);
	}

	public void setUserInfo(Map<String, String> paramMap) throws SQLException
	{
		if (paramMap.get("newflag").equals("1")) {
			smc.insert("createUser", paramMap);
		}
		else {
			int cnt = smc.update("setUser", paramMap);

			if (cnt == 0)
				smc.insert("createUser", paramMap);
		}
	}

	public void removeUserInfo(Map<String, String> paramMap) throws SQLException
	{
		smc.delete("removeUser", paramMap);
	}

	public void setUserChangePwd(Map<String, String> paramMap) throws SQLException
	{
		smc.update("setUserChangePwd", paramMap);
	}

	@SuppressWarnings("unchecked")
	public List<Object> getClientList() throws SQLException
	{
		return (List<Object>) smc.queryForList("getClientList");
	}

	@SuppressWarnings("unchecked")
	public List<Object> getClientInfo(Map<String, String> paramMap) throws SQLException
	{
		return (List<Object>) smc.queryForList("getClientInfo", paramMap);
	}

	@SuppressWarnings("unchecked")
	public List<Object> getClientRedirect(Map<String, String> paramMap) throws SQLException
	{
		return (List<Object>) smc.queryForList("getClientRedirect", paramMap);
	}

	@SuppressWarnings("unchecked")
	public List<Object> listClientRedirect(Map<String, String> paramMap) throws SQLException
	{
		return (List<Object>) smc.queryForList("listClientRedirect", paramMap);
	}

	@SuppressWarnings("unchecked")
	public List<Object> getClientScope(Map<String, String> paramMap) throws SQLException
	{
		return (List<Object>) smc.queryForList("getClientScope", paramMap);
	}

	@SuppressWarnings("unchecked")
	public List<Object> listClientScope(Map<String, String> paramMap) throws SQLException
	{
		return (List<Object>) smc.queryForList("listClientScope", paramMap);
	}

	@SuppressWarnings("unchecked")
	public List<Object> getScopeList() throws SQLException
	{
		return (List<Object>) smc.queryForList("getScopeList");
	}

	public void removeClient(Map<String, String> paramMap) throws SQLException
	{
		smc.delete("removeClient", paramMap);
		smc.delete("removeClientRedirect", paramMap);
		smc.delete("removeClientScope", paramMap);
	}

	public void setClientInfo(Map<String, Object> paramMap) throws SQLException
	{
		if (paramMap.get("newflag").equals("1")) {
			smc.insert("createClient", paramMap);
		}
		else {
			int cnt = smc.update("setClient", paramMap);

			if (cnt == 0)
				smc.insert("createClient", paramMap);
		}

		smc.delete("removeClientRedirect", paramMap);
		smc.insert("createClientRedirect", paramMap);

		smc.delete("removeClientScope", paramMap);

		if (paramMap.get("protocol").equals("OIDC"))
			smc.insert("createClientScope", paramMap);
	}

	public void removeScope(Map<String, String> paramMap) throws SQLException
	{
		smc.delete("removeScope", paramMap);
		smc.delete("removeClientScopeByScope", paramMap);
	}

	public void setScope(Map<String, Object> paramMap) throws SQLException
	{
		smc.insert("createScope", paramMap);
	}

}