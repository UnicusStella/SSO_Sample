package com.dreamsecurity.sso.server.api.audit.dao;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Map;

public interface AuditDao
{
	public Map<String, String> getStatusAudit() throws SQLException;

	public Map<String, String> getUsedRateAudit() throws SQLException;

	public ArrayList<Object> getAdminEmail() throws SQLException;

	public ArrayList<Object> getMailServer() throws SQLException;

	public ArrayList<Object> getMailSend(Map<String, String> paramMap) throws SQLException;

	public ArrayList<Object> getAupyInfo() throws SQLException;

	public int countAuditInfo(Map<String, Object> paramMap) throws SQLException;

	public ArrayList<Object> getAuditInfo(Map<String, Object> paramMap) throws SQLException;

	public ArrayList<Object> getExcelAuditInfo(Map<String, Object> paramMap) throws SQLException;

	public void setAccessLog(Map<String, String> paramMap) throws SQLException;

	public void setAuditLog(Map<String, String> paramMap) throws SQLException;

	public void setAupyInfo(Map<String, String> paramMap) throws SQLException;

	public void setMailServer(Map<String, String> paramMap) throws SQLException;

	public void setMailSend(Map<String, String> paramMap) throws SQLException;

	public void setVerifyTimeAupy() throws SQLException;

}