package com.dreamsecurity.sso.server.api.audit.dao.impl;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.dreamsecurity.sso.server.api.admin.vo.AdminVO;
import com.dreamsecurity.sso.server.api.audit.dao.AuditDao;
import com.dreamsecurity.sso.server.api.audit.vo.MailVO;
import com.dreamsecurity.sso.server.repository.ldap.dao.LdapDaoBase;
import com.dreamsecurity.sso.server.util.Util;

public class AuditLdapDaoImpl extends LdapDaoBase implements AuditDao
{
	public AuditLdapDaoImpl()
	{
		super();
	}

	@SuppressWarnings("unchecked")
	public Map<String, String> getStatusAudit() throws SQLException
	{
		Map<String, String> result = (Map<String, String>) super.selectOneData("audit.getStatusAudit", null);
		result.put("USED_RATE", "1");

		if (Util.isEmpty(result.get("VERIFY_TIME"))) {
			result.put("VERIFY_TIME", Util.addDate(Util.getDateFormat("yyyyMMddHHmm"), "yyyyMMddHHmm", Calendar.DATE, -1));
		}

		return result;
	}

	public Map<String, String> getUsedRateAudit() throws SQLException
	{
		return new HashMap<String, String>();
	}

	@SuppressWarnings("unchecked")
	public ArrayList<Object> getAdminEmail() throws SQLException
	{
		ArrayList<String> temp = new ArrayList<String>();
		ArrayList<Object> result = new ArrayList<Object>();

		ArrayList<Object> list = (ArrayList<Object>) super.selectData("admin.getAdminEmail", null);

		for (int i = 0; i < list.size(); i++) {
			AdminVO admin = (AdminVO) list.get(i);

			if (!Util.isEmpty(admin.getEmail()) && !temp.contains(admin.getEmail())) {
				result.add(list.get(i));
				temp.add(admin.getEmail());
			}
		}

		return result;
	}

	@SuppressWarnings("unchecked")
	public ArrayList<Object> getMailServer() throws SQLException
	{
		return (ArrayList<Object>) super.selectData("audit.getMailServer", null);
	}

	@SuppressWarnings("unchecked")
	public ArrayList<Object> getMailSend(Map<String, String> paramMap) throws SQLException
	{
		return (ArrayList<Object>) super.selectData("audit.getMailSend", paramMap);
	}

	@SuppressWarnings("unchecked")
	public ArrayList<Object> getAupyInfo() throws SQLException
	{
		return (ArrayList<Object>) super.selectData("audit.getAupyInfo", null);
	}

	public int countAuditInfo(Map<String, Object> paramMap) throws SQLException
	{
		return 0;
	}

	public ArrayList<Object> getAuditInfo(Map<String, Object> paramMap) throws SQLException
	{
		return new ArrayList<Object>();
	}

	public ArrayList<Object> getExcelAuditInfo(Map<String, Object> paramMap) throws SQLException
	{
		return new ArrayList<Object>();
	}

	public void setAccessLog(Map<String, String> paramMap) throws SQLException
	{
	}

	public void setAuditLog(Map<String, String> paramMap) throws SQLException
	{
	}

	public void setAupyInfo(Map<String, String> paramMap) throws SQLException
	{
		super.modifyData("audit.setAupyInfo", paramMap);
	}

	public void setMailServer(Map<String, String> paramMap) throws SQLException
	{
		List<Object> list = getMailServer();

		for (int i = 0; i < list.size(); i++) {
			MailVO mserver = (MailVO) list.get(i);

			if (Util.isEmpty(mserver.getAuthPw()) && Util.isEmpty(paramMap.get("authPw"))) {
				paramMap.remove("authPw");
			}
		}

		super.modifyData("audit.setMailServer", paramMap);
	}

	public void setMailSend(Map<String, String> paramMap) throws SQLException
	{
		List<Object> list = getMailSend(paramMap);

		for (int i = 0; i < list.size(); i++) {
			MailVO msend = (MailVO) list.get(i);

			if (Util.isEmpty(msend.getReferrer()) && Util.isEmpty(paramMap.get("referrer"))) {
				paramMap.remove("referrer");
			}
		}

		super.modifyData("audit.setMailSend", paramMap);
	}

	public void setVerifyTimeAupy() throws SQLException
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("verifyTime", Util.getDateFormat("yyyyMMddHHmmss"));

		super.modifyData("audit.setVerifyTimeAupy", paramMap);
	}
}