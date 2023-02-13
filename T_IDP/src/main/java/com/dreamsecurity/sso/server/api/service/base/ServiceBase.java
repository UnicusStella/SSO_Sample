package com.dreamsecurity.sso.server.api.service.base;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.api.admin.vo.AdminVO;
import com.dreamsecurity.sso.server.api.audit.dao.AuditDao;
import com.dreamsecurity.sso.server.api.audit.dao.impl.AuditDaoImpl;
import com.dreamsecurity.sso.server.api.audit.service.MailService;
import com.dreamsecurity.sso.server.api.audit.vo.MailVO;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.crypto.CryptoApi;
import com.dreamsecurity.sso.server.crypto.CryptoApiFactory;
import com.dreamsecurity.sso.server.repository.ldap.dao.LdapDao;
import com.dreamsecurity.sso.server.util.Util;

public class ServiceBase
{
	private static Logger log = LoggerFactory.getLogger(ServiceBase.class);

	protected static final String repositoryType = SSOConfig.getInstance().getString("repository[@type]");

	public AuditDao auditDao = null;
	public AuditDao auditDbDao = null;

	public ServiceBase()
	{
		if ("DB".equalsIgnoreCase(repositoryType)) {
			auditDao = new AuditDaoImpl();
		}
		else {
			auditDao = LdapDao.getInstance().getAuditDao();

			if (SSOConfig.getInstance().getBoolean("object-pool.dbex(0)[@usable]")) {
				auditDbDao = new AuditDaoImpl();
			}
		}
	}

	public void setAuditInfo(String caseUser, String caseType, String caseResult, String caseData)
	{
		try {
			Map<String, String> paraMap = new HashMap<String, String>();
			paraMap.put("date", Util.getDateFormat("yyyyMMdd"));
			paraMap.put("time", Util.getDateFormat("HHmmss"));
			paraMap.put("user", caseUser);
			paraMap.put("type", caseType);
			paraMap.put("result", caseResult);
			paraMap.put("detail", caseData);

			if ("DB".equalsIgnoreCase(repositoryType)) {
				auditDao.setAuditLog(paraMap);
			}
			else {
				if (auditDbDao != null) {
					auditDbDao.setAuditLog(paraMap);
				}
			}

			SSOConfig.getInstance().setDbOverflowMail(true);
		}
		catch (SQLException e) {
			log.error("### setAuditInfo() SQLException: {}, {}", e.getErrorCode(), e.toString());

			if ((e.getErrorCode() == 1653 || e.getErrorCode() == 1654)  // unable to extend table, index
					&& SSOConfig.getInstance().isDbOverflowMail()) {
				SSOConfig.getInstance().setDbOverflowMail(false);
				sendMail("MSND0004", Util.getDateFormat("yyyy-MM-dd  HH:mm:ss"), "", "");
			}
		}
	}

	public void setAuditInfo(String logDate, String logTime, String caseUser, String caseType, String caseResult, String caseData)
	{
		try {
			Map<String, String> paraMap = new HashMap<String, String>();
			paraMap.put("date", logDate);
			paraMap.put("time", logTime);
			paraMap.put("user", caseUser);
			paraMap.put("type", caseType);
			paraMap.put("result", caseResult);
			paraMap.put("detail", caseData);

			if ("DB".equalsIgnoreCase(repositoryType)) {
				auditDao.setAuditLog(paraMap);
			}
			else {
				if (auditDbDao != null) {
					auditDbDao.setAuditLog(paraMap);
				}
			}

			SSOConfig.getInstance().setDbOverflowMail(true);
		}
		catch (SQLException e) {
			log.error("### setAuditInfo() SQLException: {}, {}", e.getErrorCode(), e.toString());

			if ((e.getErrorCode() == 1653 || e.getErrorCode() == 1654)  // unable to extend table, index
					&& SSOConfig.getInstance().isDbOverflowMail()) {
				SSOConfig.getInstance().setDbOverflowMail(false);
				sendMail("MSND0004", Util.getDateFormat("yyyy-MM-dd  HH:mm:ss"), "", "");
			}
		}
	}

	public boolean sendMail(String code, String time, String param1, String param2)
	{
		boolean result = false;

		String detail = "";
		if (code.equals("MSND0000"))
			detail = "인증 기능 비활성화 알림";
		else if (code.equals("MSND0001"))
			detail = "SSO모듈 무결성 검증 오류 알림";
		else if (code.equals("MSND0002"))
			detail = "암호모듈 자가시험 오류 알림";
		else if (code.equals("MSND0003"))
			detail = "감사정보 저장용량 임계치 초과 알림";
		else if (code.equals("MSND0004"))
			detail = "감사정보 저장소 포화상태 알림";
		else if (code.equals("MSND0005"))
			detail = "SSO 프로세스 검증 오류 알림";

		try {
			ArrayList<Object> smtplist = getMailServer();
			MailVO smtpInfo = (MailVO) smtplist.get(0);

			if (Util.isEmpty(smtpInfo.getSmtpHost()) || Util.isEmpty(smtpInfo.getSmtpPort()) ||
					Util.isEmpty(smtpInfo.getSmtpChnl()) || Util.isEmpty(smtpInfo.getAuthId())) {
				if (!code.equals("MSND0004")) {
					setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), SSOConfig.getInstance().getServerName(),
							"AY", "1", detail + ", 메일서버 정보 없음");
				}
				return result;
			}

			ArrayList<Object> emaillist = getAdminEmail();
			List<String> recipient = new ArrayList<String>();
			for (int i = 0; i < emaillist.size(); i++) {
				AdminVO al = (AdminVO) emaillist.get(i);
				if (!Util.isEmpty(al.getEmail())) {
					recipient.add(al.getEmail());
				}
			}

			if (recipient.size() == 0) {
				if (!code.equals("MSND0004")) {
					setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), SSOConfig.getInstance().getServerName(),
							"AY", "1", detail + ", 수신자 정보 없음");
				}
				return result;
			}

			ArrayList<Object> sendlist = getMailSend(code);
			MailVO sendInfo = (MailVO) sendlist.get(0);

			String referrer = sendInfo.getReferrer() == null ? "" : sendInfo.getReferrer();
			String subject = sendInfo.getSubject() == null ? "" : sendInfo.getSubject();
			String content = sendInfo.getContent() == null ? "" : sendInfo.getContent();

			if (code.equals("MSND0000")) {
				content = content.replace("$1", param1);
				content = content.replace("$2", param2);
			}
			else if (!code.equals("MSND0004")) {
				subject = subject + " (" + param1 + ")";
			}

			content = content + "\n발생 일시 : " + time;

			MailService sendMail = new MailService(smtpInfo);
			sendMail.setContent(code, recipient, referrer, subject, content);
			new Thread(sendMail).start();

			result = true;
		}
		catch (SQLException e) {
			setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), SSOConfig.getInstance().getServerName(),
					"AY", "1", detail);

			log.error("### sendMail() SQLException : {} : {}", e.getErrorCode(), e.getMessage());
			e.printStackTrace();
		}
		catch (Exception e) {
			setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), SSOConfig.getInstance().getServerName(),
					"AY", "1", detail);

			log.error("### sendMail() Exception : {}", e.getMessage());
			e.printStackTrace();
		}

		return result;
	}

	public ArrayList<Object> getAdminEmail() throws Exception
	{
		return auditDao.getAdminEmail();
	}

	public ArrayList<Object> getMailServer() throws Exception
	{
		ArrayList<Object> list = auditDao.getMailServer();

		CryptoApi crypto = CryptoApiFactory.getCryptoApi();

		for (int i = 0; i < list.size(); i++) {
			MailVO mail = (MailVO) list.get(i);

			String decSmtpHost = "";
			String decSmtpPort = "";
			String decSmtpChnl = "";
			String decSmtpAuth = "";
			String decAuthId = "";
			String decAuthPw = "";

			if (!Util.isEmpty(mail.getSmtpHost())) { decSmtpHost = new String(crypto.decryptByDEK(mail.getSmtpHost())); }
			if (!Util.isEmpty(mail.getSmtpPort())) { decSmtpPort = new String(crypto.decryptByDEK(mail.getSmtpPort())); }
			if (!Util.isEmpty(mail.getSmtpChnl())) { decSmtpChnl = new String(crypto.decryptByDEK(mail.getSmtpChnl())); }
			if (!Util.isEmpty(mail.getSmtpAuth())) { decSmtpAuth = new String(crypto.decryptByDEK(mail.getSmtpAuth())); }
			if (!Util.isEmpty(mail.getAuthId())) { decAuthId = new String(crypto.decryptByDEK(mail.getAuthId())); }
			if (!Util.isEmpty(mail.getAuthPw())) { decAuthPw = new String(crypto.decryptByDEK(mail.getAuthPw())); }

			mail.setSmtpHost(decSmtpHost);
			mail.setSmtpPort(decSmtpPort);
			mail.setSmtpChnl(decSmtpChnl);
			mail.setSmtpAuth(decSmtpAuth);
			mail.setAuthId(decAuthId);
			mail.setAuthPw(decAuthPw);
		}

		return list;
	}

	public ArrayList<Object> getMailSend(String code) throws Exception
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("code", code);

		ArrayList<Object> list = auditDao.getMailSend(paramMap);

		CryptoApi crypto = CryptoApiFactory.getCryptoApi();

		for (int i = 0; i < list.size(); i++) {
			MailVO mail = (MailVO) list.get(i);

			String decReferrer = "";
			String decSubject = "";
			String decContent = "";

			if (!Util.isEmpty(mail.getReferrer())) { decReferrer = new String(crypto.decryptByDEK(mail.getReferrer())); }
			if (!Util.isEmpty(mail.getSubject())) { decSubject = new String(crypto.decryptByDEK(mail.getSubject())); }
			if (!Util.isEmpty(mail.getContent())) { decContent = new String(crypto.decryptByDEK(mail.getContent())); }

			mail.setReferrer(decReferrer);
			mail.setSubject(decSubject);
			mail.setContent(decContent);
		}

		return list;
	}
}