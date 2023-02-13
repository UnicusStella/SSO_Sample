package com.dreamsecurity.sso.server.repository.connection;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.dreamsecurity.sso.lib.ism.client.SqlMapClient;
import com.dreamsecurity.sso.lib.jtm.DateTime;
import com.dreamsecurity.sso.lib.jtm.DateTimeZone;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.api.audit.AuditController;
import com.dreamsecurity.sso.server.api.audit.service.AuditService;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.repository.ldap.dao.LdapDao;
import com.dreamsecurity.sso.server.repository.ldap.pool.LdapPoolLoader;
import com.dreamsecurity.sso.server.session.AuthnIssue;
import com.dreamsecurity.sso.server.session.OidcSessionManager;
import com.dreamsecurity.sso.server.session.RootAuthSession;
import com.dreamsecurity.sso.server.session.SessionManager;
import com.dreamsecurity.sso.server.token.OAuth2Code;
import com.dreamsecurity.sso.server.util.Util;

public class DBConnectMonitor implements Runnable
{
	private static Logger log = LoggerFactory.getLogger(DBConnectMonitor.class);

	private static String repositoryType = SSOConfig.getInstance().getString("repository[@type]");

	private boolean isContinue;
	private long interval;
	private String dbname;
	private String arrangeWork = "";

	public DBConnectMonitor(String dbname)
	{
		this.dbname = dbname;
	}

	public void setContinue(boolean isContinue)
	{
		this.isContinue = isContinue;
	}

	public void setInterval(long interval)
	{
		this.interval = interval;
	}

	public void run()
	{
		log.debug("### {} Monitor Start ...", dbname);

		while (this.isContinue) {
			try {
				for (int i = 0; i < this.interval; i++) {
					if (this.isContinue) {
						Thread.sleep(1000);
					}
					else {
						break;
					}
				}

				if (!this.isContinue) {
					break;
				}
			}
			catch (InterruptedException e) {
				e.printStackTrace();
			}

			log.info("### {} Connect Test Start ...", dbname);
			long startTime = System.currentTimeMillis();

			if ("DB".equalsIgnoreCase(repositoryType)) {
				try {
					((SqlMapClient) DBConnectMap.getInstance().getConnection(dbname)).queryForObject(dbname + "_connCheck");
					log.info("### {} Status is Good [ {} ms.]", dbname, System.currentTimeMillis() - startTime);
				}
				catch (Exception e) {
					e.printStackTrace();
					log.error("### {} Reconnecting Start ... [ {} ms.]", dbname, System.currentTimeMillis() - startTime);

					DBConnectMap.getInstance().createDBConnection(dbname);
				}
			}
			else {
				try {
					LdapDao.getInstance().getAdminDao().getAdminList();
					log.info("### LDAP Status is Good [ {} ms.]", System.currentTimeMillis() - startTime);
				}
				catch (Exception e) {
					e.printStackTrace();
					log.error("### LDAP Reconnecting Start ... [ {} ms.]", System.currentTimeMillis() - startTime);

					LdapPoolLoader.getInstance().createLdapPools();
				}

				if (SSOConfig.getInstance().getBoolean("object-pool.dbex(0)[@usable]")) {
					String dbexName = SSOConfig.getInstance().getString("object-pool.dbex(0)[@name]");
					try {
						((SqlMapClient) DBConnectMap.getInstance().getConnection(dbexName)).queryForObject(dbexName + "_connCheck");
						log.info("### {} Status is Good [ {} ms.]", dbexName, System.currentTimeMillis() - startTime);
					}
					catch (Exception e) {
						e.printStackTrace();
						log.error("### {} Reconnecting Start ... [ {} ms.]", dbexName, System.currentTimeMillis() - startTime);

						DBConnectMap.getInstance().createDBConnection(dbexName);
					}
				}
			}

			checkAudit();
			clearSessionMap();
		}
	}

	public void checkAudit()
	{
		try {
			AuditService auditApi = new AuditService();

			Map<String, String> statusMap = auditApi.getStatusAudit();

			int nWarnLimit = Integer.parseInt((String) statusMap.get("WARN_LIMIT"));
			int nUsed = Integer.parseInt((String) statusMap.get("USED_RATE"));

			if (nWarnLimit < nUsed) {
				if (SSOConfig.getInstance().isDbCriticalMail()) {
					auditApi.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), SSOConfig.getInstance().getServerName(),
							"AE", "0", statusMap.get("WARN_LIMIT") + "% 초과");

					auditApi.sendMail("MSND0003", Util.getDateFormat("yyyy-MM-dd  HH:mm:ss"), statusMap.get("WARN_LIMIT") + "% 초과", "");
				}
			}
			else {
				SSOConfig.getInstance().setDbCriticalMail(true);
			}

			// Integrity
			String verifyCycle = statusMap.get("VERIFY_CYCLE");
			String verifyPoint =  statusMap.get("VERIFY_POINT");
			String verifyTime = statusMap.get("VERIFY_TIME");

			if (verifyCycle.equals("M")) { // 매시 몇 분에
				SimpleDateFormat sdFormat = new SimpleDateFormat("yyyyMMddHHmm");
				String curTime = sdFormat.format(new Date());
				String workTime1 = curTime.substring(0, 10) + (verifyPoint.length() == 1 ? '0' + verifyPoint : verifyPoint);
				String workTime2 = Util.addDate(workTime1, "yyyyMMddHHmm", Calendar.MINUTE, 5);

				if (verifyTime.compareTo(workTime1) < 0) {
					if (workTime1.compareTo(curTime) <= 0 && workTime2.compareTo(curTime) > 0) {
						auditApi.setVerifyTimeAupy();

						AuditController auditCtrl = new AuditController(auditApi);
						auditCtrl.integrityIDPTestSync(SSOConfig.getInstance().getServerName(), "정기 테스트");
						auditCtrl.integrityAllSPTest("system", "정기 테스트");
					}
				}
			}
			else if (verifyCycle.equals("H")) { // 매일 몇 시에
				SimpleDateFormat sdFormat = new SimpleDateFormat("yyyyMMddHH");
				String curTime = sdFormat.format(new Date());
				String workTime = curTime.substring(0, 8) + (verifyPoint.length() == 1 ? '0' + verifyPoint : verifyPoint);
				verifyTime = verifyTime.substring(0, 10);

				if (verifyTime.compareTo(workTime) < 0) {
					if (workTime.compareTo(curTime) == 0) {
						auditApi.setVerifyTimeAupy();

						AuditController auditCtrl = new AuditController(auditApi);
						auditCtrl.integrityIDPTestSync(SSOConfig.getInstance().getServerName(), "정기 테스트");
						auditCtrl.integrityAllSPTest("system", "정기 테스트");
					}
				}
			}
			else if (verifyCycle.equals("D")) { // 매월 몇 일에
				SimpleDateFormat sdFormat = new SimpleDateFormat("yyyyMMdd");
				String curTime = sdFormat.format(new Date());
				String workTime = curTime.substring(0, 6) + (verifyPoint.length() == 1 ? '0' + verifyPoint : verifyPoint);
				verifyTime = verifyTime.substring(0, 8);

				if (verifyTime.compareTo(workTime) < 0) {
					if (workTime.compareTo(curTime) == 0) {
						auditApi.setVerifyTimeAupy();

						AuditController auditCtrl = new AuditController(auditApi);
						auditCtrl.integrityIDPTestSync(SSOConfig.getInstance().getServerName(), "정기 테스트");
						auditCtrl.integrityAllSPTest("system", "정기 테스트");
					}
				}
			}
			else {
			}
		}
		catch (Exception e) {
			log.error("### checkAudit() Exception : {}", e.toString());
			e.printStackTrace();
		}
	}

	public void clearSessionMap()
	{
		try {
			DateTime dateTime = new DateTime(DateTimeZone.UTC).minusMinutes(SSOConfig.getInstance().getRequestTimeout());
			List<String> removeKey = new ArrayList<String>();

			Map<String, DateTime> authnMap = SessionManager.getInstance().getAuthnMap();
			Map<String, DateTime> authnNLMap = SessionManager.getInstance().getAuthnNLMap();
			Map<String,Object> authcodeMap = SessionManager.getInstance().getAuthcodeMap();

			Map<String, RootAuthSession> rootAuthSessionMap = OidcSessionManager.getInstance().getRootAuthSessionMap();
			Map<String, OAuth2Code> oauth2CodeMap = OidcSessionManager.getInstance().getOauth2CodeMap();

			// AuthnMap
			Iterator<String> iter = authnMap.keySet().iterator();

			while (iter.hasNext()) {
				String key = iter.next();
				DateTime issueTime = authnMap.get(key);

				if (dateTime.compareTo(issueTime) > 0) {
					removeKey.add(key);
				}
			}

			for (int i = 0; i < removeKey.size(); i++) {
				authnMap.remove(removeKey.get(i));
			}

			// AuthnNLMap
			removeKey.clear();
			Iterator<String> iterNL = authnNLMap.keySet().iterator();

			while (iterNL.hasNext()) {
				String key = iterNL.next();
				DateTime issueTime = authnNLMap.get(key);

				if (dateTime.compareTo(issueTime) > 0) {
					removeKey.add(key);
				}
			}

			for (int i = 0; i < removeKey.size(); i++) {
				authnNLMap.remove(removeKey.get(i));
			}

			// AuthcodeMap (default: 04시에, 6시간 경과된 코드 삭제)
			List<String> defaultTime = new ArrayList<String>();
			defaultTime.add("04");

			List<?> arrangeTime = SSOConfig.getInstance().getList("authmap.arrange.time", defaultTime);
			int arrangeHours = SSOConfig.getInstance().getInt("authmap.arrange.hours", 6);

			if (arrangeTime == null || arrangeTime.size() == 0 || arrangeHours == 0) {
				return;
			}

			SimpleDateFormat sdFormat = new SimpleDateFormat("HH");
			String curHour = sdFormat.format(new Date());

			if (!arrangeTime.contains(curHour) || arrangeWork.equals(curHour)) {
				return;
			}
			else {
				arrangeWork = curHour;
			}

			Iterator<Entry<String,Object>> iterAuth = authcodeMap.entrySet().iterator();

			while (iterAuth.hasNext()) {
				Entry<String,Object> entry = (Entry<String,Object>) iterAuth.next();
				AuthnIssue authnissue = (AuthnIssue) entry.getValue();

				DateTime validTime = authnissue.getIssueTime().plusHours(arrangeHours);
				DateTime curTime = new DateTime();

				if (validTime.compareTo(curTime) < 0) {
					iterAuth.remove();
				}
			}

			// RootAuthSession
			Iterator<Entry<String, RootAuthSession>> iterRootAuthSession = rootAuthSessionMap.entrySet().iterator();

			while (iterRootAuthSession.hasNext()) {
				Entry<String, RootAuthSession> entry = (Entry<String, RootAuthSession>) iterRootAuthSession.next();
				RootAuthSession rootAuthSession = (RootAuthSession) entry.getValue();

				DateTime validTime = rootAuthSession.getExpDate();
				DateTime curTime = new DateTime();

				if (validTime.compareTo(curTime) < 0) {
					iterRootAuthSession.remove();
				}
			}

			// oauth2Code
			Iterator<Entry<String, OAuth2Code>> iterOauth2Code = oauth2CodeMap.entrySet().iterator();

			while (iterOauth2Code.hasNext()) {
				Entry<String, OAuth2Code> entry = (Entry<String, OAuth2Code>) iterOauth2Code.next();
				OAuth2Code oauth2Code = (OAuth2Code) entry.getValue();

				DateTime validTime = oauth2Code.getExpDate();
				DateTime curTime = new DateTime();

				if (validTime.compareTo(curTime) < 0) {
					iterOauth2Code.remove();
				}
			}
		}
		catch (Exception e) {
			log.error("### clearSessionMap() Exception : {}", e.getMessage());
			e.printStackTrace();
		}
	}
}