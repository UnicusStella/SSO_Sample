package com.dreamsecurity.sso.server.api.admin.dao.impl;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.dreamsecurity.sso.server.api.admin.dao.AdminDao;
import com.dreamsecurity.sso.server.api.admin.vo.AdminVO;
import com.dreamsecurity.sso.server.api.user.vo.UserVO;
import com.dreamsecurity.sso.server.repository.ldap.dao.LdapDaoBase;
import com.dreamsecurity.sso.server.util.Util;

public class AdminLdapDaoImpl extends LdapDaoBase implements AdminDao
{
	public AdminLdapDaoImpl()
	{
		super();
	}

	@SuppressWarnings("unchecked")
	public Map<String, String> getAdminByID(Map<String, String> paramMap) throws SQLException
	{
		Map<String,String> adminMap = (Map<String,String>) super.selectOneData("admin.getAdminByID", paramMap);

		if (adminMap.size() > 1) {
			paramMap.put("code", adminMap.get("POLICY_CODE"));

			adminMap.putAll((Map<String,String>) super.selectOneData("admin.getPolicy", paramMap));
		}

		return adminMap;
	}

	@SuppressWarnings("unchecked")
	public List<Object> getAdminIpList() throws SQLException
	{
		return (List<Object>) super.selectData("admin.getAdminIpList", null);
	}

	@SuppressWarnings("unchecked")
	public List<AdminVO> getUsingAdmin() throws SQLException
	{
		return (List<AdminVO>) super.selectData("admin.getUsingAdmin", null);
	}

	@SuppressWarnings("unchecked")
	public List<Object> getAdminList() throws SQLException
	{
		return (List<Object>) super.selectData("admin.getAdminList", null);
	}

	@SuppressWarnings("unchecked")
	public List<Object> getAdminInfo(Map<String, String> paramMap) throws SQLException
	{
		return (List<Object>) super.selectData("admin.getAdminInfo", paramMap);
	}

	@SuppressWarnings("unchecked")
	public List<Object> getAdpyInfo(Map<String, String> paramMap) throws SQLException
	{
		return (List<Object>) super.selectData("admin.getAdpyInfo", paramMap);
	}

	@SuppressWarnings("unchecked")
	public List<Object> getUrpyInfo(Map<String, String> paramMap) throws SQLException
	{
		return (List<Object>) super.selectData("admin.getUrpyInfo", paramMap);
	}

	public int countUserLockedList() throws SQLException
	{
		return super.selectCount("user.getUserLockedList", null);
	}

	@SuppressWarnings("unchecked")
	public ArrayList<Object> getUserLockedList(Map<String, Object> paramMap) throws SQLException
	{
		ArrayList<Object> result = new ArrayList<Object>();

		int frNum = (Integer) paramMap.get("fnum");
		int toNum = (Integer) paramMap.get("tnum");

		List<Object> lockedList = (List<Object>) super.selectData("user.getUserLockedList", null);

		for (int i = 0; i < lockedList.size(); i++) {
			if (i >= (frNum - 1) && i < toNum) {
				UserVO user = (UserVO) lockedList.get(i);
				user.setIndex(String.valueOf(i+1));
				result.add(user);
			}
		}

		return result;
	}

	public int countUserListByVal(Map<String, String> paramMap) throws SQLException
	{
		if (!Util.isEmpty((String) paramMap.get("userId"))) {
			return super.selectCount("user.getUserListById", paramMap);
		}
		else if (!Util.isEmpty((String) paramMap.get("userName"))) {
			return super.selectCount("user.getUserListByName", paramMap);
		}
		else {
			return super.selectCount("user.getAllUserList", null);
		}
	}

	@SuppressWarnings("unchecked")
	public List<Object> getUserListByVal(Map<String, Object> paramMap) throws SQLException
	{
		ArrayList<Object> result = new ArrayList<Object>();

		int frNum = (Integer) paramMap.get("fnum");
		int toNum = (Integer) paramMap.get("tnum");

		List<Object> userList = null;

		if (!Util.isEmpty((String) paramMap.get("userId"))) {
			userList = super.selectData("user.getUserListById", paramMap);
		}
		else if (!Util.isEmpty((String) paramMap.get("userName"))) {
			userList = super.selectData("user.getUserListByName", paramMap);
		}
		else {
			userList = super.selectData("user.getAllUserList", null);
		}

		for (int i = 0; i < userList.size(); i++) {
			if (i >= (frNum - 1) && i < toNum) {
				UserVO user = (UserVO) userList.get(i);
				user.setIndex(String.valueOf(i+1));
				result.add(user);
			}
		}

		return result;
	}

	@SuppressWarnings("unchecked")
	public int getUserRowByVal(Map<String, String> paramMap) throws SQLException
	{
		int cnt = 0;

		List<Object> userList = (List<Object>) super.selectData("user.getAllUserList", null);

		for (int i = 0; i < userList.size(); i++) {
			UserVO user = (UserVO) userList.get(i);

			if (Util.isEmpty(paramMap.get("userName"))) {
				if (user.getId().indexOf(paramMap.get("userId")) == 0) {
					cnt = i + 1;
					break;
				}
			}
			else {
				if (user.getName().indexOf(paramMap.get("userName")) == 0) {
					cnt = i + 1;
					break;
				}
			}
		}

		return cnt;
	}

	public int countUserList() throws SQLException
	{
		return super.selectCount("user.getAllUserList", null);
	}

	@SuppressWarnings("unchecked")
	public ArrayList<Object> getUserList(Map<String, Object> paramMap) throws SQLException
	{
		ArrayList<Object> result = new ArrayList<Object>();

		int frNum = (Integer) paramMap.get("fnum");
		int toNum = (Integer) paramMap.get("tnum");

		List<Object> userList = (List<Object>) super.selectData("user.getAllUserList", null);

		for (int i = 0; i < userList.size(); i++) {
			if (i >= (frNum - 1) && i < toNum) {
				result.add(userList.get(i));
			}
		}

		return result;
	}

	@SuppressWarnings("unchecked")
	public List<Object> getUserInfo(Map<String, String> paramMap) throws SQLException
	{
		return (List<Object>) super.selectData("user.getUserInfo", paramMap);
	}

	public int countUserAccessInfo(Map<String, Object> paramMap) throws SQLException
	{
		return 0;
	}

	public ArrayList<Object> getUserAccessInfo(Map<String, Object> paramMap) throws SQLException
	{
		return new ArrayList<Object>();
	}

	public ArrayList<Object> getExcelAccessInfo(Map<String, Object> paramMap) throws SQLException
	{
		return new ArrayList<Object>();
	}

	public ArrayList<Object> getStatsDateAccessInfo(Map<String, Object> paramMap) throws SQLException
	{
		return new ArrayList<Object>();
	}

	public ArrayList<Object> getStatsMonthAccessInfo(Map<String, Object> paramMap) throws SQLException
	{
		return new ArrayList<Object>();
	}

	public ArrayList<Object> getStatsYearAccessInfo(Map<String, Object> paramMap) throws SQLException
	{
		return new ArrayList<Object>();
	}

	public void setAdminStatus(Map<String, String> paramMap) throws SQLException
	{
		paramMap.put("count", "0");
		paramMap.put("access", Util.getDateFormat("yyyyMMddHHmmss"));

		super.modifyData("admin.setAdminStatus", paramMap);
	}

	public void setAdminPWMismatchCount(String id, String count, String status) throws SQLException
	{
		String curTime = Util.getDateFormat("yyyyMMddHHmmss");

		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("id", id);
		paramMap.put("count", count);
		paramMap.put("status", status);
		paramMap.put("access", curTime);

		if (status.equals("D")) {
			paramMap.put("lock", curTime);

			super.modifyData("admin.setAdminPWMismatchLock", paramMap);
			return;
		}

		super.modifyData("admin.setAdminPWMismatchCount", paramMap);
	}

	public void setAdminFirstYn(String id) throws SQLException
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("id", id);
		paramMap.put("first", "N");

		super.modifyData("admin.setAdminFirstYn", paramMap);
	}

	public void setAdminUseYn() throws SQLException
	{
		List<Object> list = getAdminList();

		for (int i = 0; i < list.size(); i++) {
			AdminVO admin = (AdminVO) list.get(i);
			
			Map<String, String> paramMap = new HashMap<String, String>();
			paramMap.put("id", admin.getId());
			paramMap.put("use", "N");

			super.modifyData("admin.setAdminUseYn", paramMap);
		}
	}

	public void setAdminAccessInfo(String id, String ip, String br, String tp) throws SQLException
	{
		String curTime = Util.getDateFormat("yyyyMMddHHmmss");

		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("id", id);
		paramMap.put("ip", ip);
		paramMap.put("br", br);
		paramMap.put("access", curTime);
		paramMap.put("count", "0");

		if (tp.equals("S")) {
			paramMap.put("use", "Y");

			setAdminUseYn();
			super.modifyData("admin.setAdminLoginInfo", paramMap);
		}
		else {
			paramMap.put("use", "N");

			super.modifyData("admin.setAdminLoginInfo", paramMap);
		}
	}

	public void setAdminLogoutInfo(String id) throws SQLException
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("id", id);
		paramMap.put("use", "N");

		super.modifyData("admin.setAdminLogoutInfo", paramMap);
	}

	@SuppressWarnings("unchecked")
	public int setAdminPwd(Map<String, String> paramMap) throws SQLException
	{
		Map<String,String> adminMap = (Map<String,String>) super.selectOneData("admin.getAdminByID", paramMap);

		if (adminMap.size() > 1) {
			if (adminMap.get("PASSWORD").equals(paramMap.get("curPwd"))) {
				super.modifyData("admin.setAdminPwd", paramMap);
				return 1;
			}
			else {
				return 0;
			}
		}

		return 0;
	}

	public void setAdminInfo(Map<String, String> paramMap) throws SQLException
	{
		if (paramMap.get("newflag").equals("1")) {
			paramMap.put("status", "C");
			paramMap.put("count", "0");
			paramMap.put("code", "ADPY001");
			paramMap.put("first", "Y");

			super.addData("admin.createAdmin", paramMap);
		}
		else {
			List<Object> list = getAdminInfo(paramMap);

			for (int i = 0; i < list.size(); i++) {
				AdminVO admin = (AdminVO) list.get(i);

				if (Util.isEmpty(admin.getEmail()) && Util.isEmpty(paramMap.get("email"))) {
					paramMap.remove("email");
				}

				if (Util.isEmpty(admin.getMenuCode()) && Util.isEmpty(paramMap.get("menucode"))) {
					paramMap.remove("menucode");
				}
			}

			super.modifyData("admin.setAdmin", paramMap);
		}
	}

	public void removeAdminInfo(Map<String, String> paramMap) throws SQLException
	{
		super.removeData("admin.removeAdmin", paramMap);
	}

	public void setAdpyInfo(Map<String, String> paramMap) throws SQLException
	{
		super.modifyData("admin.setAdpyInfo", paramMap);
	}

	public void setAdminIp(Map<String, String> paramMap) throws SQLException
	{
		super.addData("admin.createAdminIp", paramMap);
	}

	public void removeAdminIp(Map<String, String> paramMap) throws SQLException
	{
		super.removeData("admin.removeAdminIp", paramMap);
	}

	@SuppressWarnings("unchecked")
	public void setUserUnlock(Map<String, String> paramMap) throws SQLException
	{
		Map<String,String> userMap = (Map<String,String>) super.selectOneData("user.getUserByID", paramMap);

		if (userMap.size() > 1) {
			paramMap.put("status", "C");
			paramMap.put("count", "0");
			paramMap.put("loginTime", Util.getDateFormat("yyyyMMddHHmmss"));

			if (!Util.isEmpty(userMap.get("NOW_LOGIN_IP"))) {
				paramMap.put("loginIp", "");
			}
			if (!Util.isEmpty(userMap.get("NOW_LOGIN_BR"))) {
				paramMap.put("loginBr", "");
			}

			super.modifyData("user.setUserUnlock", paramMap);
		}

		return;
	}

	public void setUrpyInfo(Map<String, String> paramMap) throws SQLException
	{
		super.modifyData("admin.setUrpyInfo", paramMap);
	}

	public void setUserInfo(Map<String, String> paramMap) throws SQLException
	{
		if (paramMap.get("newflag").equals("1")) {
			paramMap.put("status", "C");
			paramMap.put("count", "0");
			paramMap.put("code", "URPY001");

			super.addData("user.createUser", paramMap);
		}
		else {
			super.modifyData("user.setUser", paramMap);
		}
	}

	public void removeUserInfo(Map<String, String> paramMap) throws SQLException
	{
		super.removeData("user.removeUser", paramMap);
	}

	public void setUserChangePwd(Map<String, String> paramMap) throws SQLException
	{

	}

	public List<Object> getClientList() throws SQLException
	{
		return null;
	}

	public List<Object> getClientInfo(Map<String, String> paramMap) throws SQLException
	{
		return null;
	}

	public List<Object> getClientRedirect(Map<String, String> paramMap) throws SQLException
	{
		return null;
	}

	public List<Object> listClientRedirect(Map<String, String> paramMap) throws SQLException
	{
		return null;
	}

	public List<Object> getClientScope(Map<String, String> paramMap) throws SQLException
	{
		return null;
	}

	public List<Object> listClientScope(Map<String, String> paramMap) throws SQLException
	{
		return null;
	}
	
	public List<Object> getScopeList() throws SQLException
	{
		return null;
	}

	public void removeClient(Map<String, String> paramMap) throws SQLException
	{
	}

	public void setClientInfo(Map<String, Object> paramMap) throws SQLException
	{
	}

	public void removeScope(Map<String, String> paramMap) throws SQLException
	{
	}

	public void setScope(Map<String, Object> paramMap) throws SQLException
	{
	}
}