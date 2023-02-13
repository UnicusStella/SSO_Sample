package com.dreamsecurity.sso.server.api.audit.dao.impl;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Map;

import com.dreamsecurity.sso.server.api.audit.dao.AuditDao;
import com.dreamsecurity.sso.server.repository.connection.DBConnectMap;
import com.dreamsecurity.sso.lib.ism.client.SqlMapClient;

public class AuditDaoImpl implements AuditDao
{
	private SqlMapClient smc = null;

	public AuditDaoImpl()
	{
		smc = DBConnectMap.getInstance().getConnection("default_db");
	}

	@SuppressWarnings("unchecked")
	public Map<String, String> getStatusAudit() throws SQLException
	{
		return (Map<String, String>) smc.queryForObject("getStatusAudit");
	}

	@SuppressWarnings("unchecked")
	public Map<String, String> getUsedRateAudit() throws SQLException
	{
		return (Map<String, String>) smc.queryForObject("getUsedRateAudit");
	}

	@SuppressWarnings("unchecked")
	public ArrayList<Object> getAdminEmail() throws SQLException
	{
		return (ArrayList<Object>) smc.queryForList("getAdminEmail");
	}

	@SuppressWarnings("unchecked")
	public ArrayList<Object> getMailServer() throws SQLException
	{
		return (ArrayList<Object>) smc.queryForList("getMailServer");
	}

	@SuppressWarnings("unchecked")
	public ArrayList<Object> getMailSend(Map<String, String> paramMap) throws SQLException
	{
		return (ArrayList<Object>) smc.queryForList("getMailSend", paramMap);
	}

	@SuppressWarnings("unchecked")
	public ArrayList<Object> getAupyInfo() throws SQLException
	{
		return (ArrayList<Object>) smc.queryForList("getAupyInfo");
	}

	@SuppressWarnings("unchecked")
	public int countAuditInfo(Map<String, Object> paramMap) throws SQLException
	{
		int cnt = 0;
		Map<String, Object> resultMap = null;

		resultMap = (Map<String, Object>) smc.queryForObject("countAuditInfo", paramMap);

		if (resultMap.size() == 1) {
			String temp = String.valueOf(resultMap.get("CNT"));
			cnt = Integer.parseInt(temp);
		}

		return cnt;
	}

	@SuppressWarnings("unchecked")
	public ArrayList<Object> getAuditInfo(Map<String, Object> paramMap) throws SQLException
	{
		return (ArrayList<Object>) smc.queryForList("getAuditInfo", paramMap);
	}

	@SuppressWarnings("unchecked")
	public ArrayList<Object> getExcelAuditInfo(Map<String, Object> paramMap) throws SQLException
	{
		return (ArrayList<Object>) smc.queryForList("getExcelAuditInfo", paramMap);
	}

	public void setAccessLog(Map<String, String> paramMap) throws SQLException
	{
		smc.insert("setAccessLog", paramMap);
	}

	public void setAuditLog(Map<String, String> paramMap) throws SQLException
	{
		if (smc != null) {
			smc.insert("setAuditLog", paramMap);
		}
	}

	public void setAupyInfo(Map<String, String> paramMap) throws SQLException
	{
		smc.update("setAupyInfo", paramMap);
	}

	public void setMailServer(Map<String, String> paramMap) throws SQLException
	{
		smc.update("setMailServer", paramMap);
	}

	public void setMailSend(Map<String, String> paramMap) throws SQLException
	{
		smc.update("setMailSend", paramMap);
	}

	public void setVerifyTimeAupy() throws SQLException
	{
		smc.update("setVerifyTimeAupy");
	}

}