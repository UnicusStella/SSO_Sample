package com.dreamsecurity.sso.server.api.audit;

import java.io.File;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import jxl.Workbook;
import jxl.write.Label;
import jxl.write.WritableSheet;
import jxl.write.WritableWorkbook;

import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.lib.dss.s2.metadata.Endpoint;
import com.dreamsecurity.sso.server.api.admin.vo.AdminVO;
import com.dreamsecurity.sso.server.api.audit.service.AuditService;
import com.dreamsecurity.sso.server.api.audit.service.MailService;
import com.dreamsecurity.sso.server.api.audit.vo.AuditListVO;
import com.dreamsecurity.sso.server.api.audit.vo.MailVO;
import com.dreamsecurity.sso.server.api.audit.vo.ServerVO;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.crypto.SSOCryptoApi;
import com.dreamsecurity.sso.server.ha.SyncMonitor;
import com.dreamsecurity.sso.server.metadata.MetadataRepository;
import com.dreamsecurity.sso.server.provider.IdentificationProvider;
import com.dreamsecurity.sso.server.util.JsonUtil;
import com.dreamsecurity.sso.server.util.Util;

public class AuditController
{
	private static Logger log = LoggerFactory.getLogger(AuditController.class);

	private AuditService service = null;

	public AuditController()
	{
		this.service = new AuditService();
	}

	public AuditController(AuditService service)
	{
		this.service = service;
	}

	public String getAupyInfo()
	{
		String pString = "";

		try {
			ArrayList<Object> arraylist = service.getAupyInfo();

			List<String> key = new ArrayList<String>();
			key.add("warnCycle");
			key.add("warnLimit");
			key.add("verifyCycle");
			key.add("verifyPoint");

			pString = JsonUtil.jqgridPaser(key, arraylist);
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류";
			e.printStackTrace();
		}

		return pString;
	}

	public String setAupyInfo(String adminid, String warnlimit, String verifycycle, String verifypoint)
	{
		String pString = "";

		try {
			service.setAupyInfo(warnlimit, verifycycle, verifypoint);

			StringBuilder sb = new StringBuilder();
			sb.append("저장 용량 임계치:" + warnlimit + "%");
			sb.append(", 모듈 검증 주기:");
			if (verifycycle.equals("M")) {
				sb.append("매시 " + verifypoint + "분");
			}
			else if (verifycycle.equals("H")) {
				sb.append("매일 " + verifypoint + "시");
			}
			else if (verifycycle.equals("D")) {
				sb.append("매월 " + verifypoint + "일");
			}

			service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					adminid, "AF", "0", sb.toString());

			pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
		}
		catch (Exception e) {
			pString = "Error : 데이터 저장 오류";
			e.printStackTrace();
		}

		return pString;
	}

	public String getMailServer()
	{
		String pString = "";

		try {
			ArrayList<Object> arraylist = service.getMailServer();

			List<String> key = new ArrayList<String>();
			key.add("smtpHost");
			key.add("smtpPort");
			key.add("smtpChnl");
			key.add("smtpAuth");
			key.add("authId");
			key.add("authPw");

			pString = JsonUtil.jqgridPaser(key, arraylist);
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류";
			e.printStackTrace();
		}

		return pString;
	}

	public String setMailServer(String adminid, String smtpHost, String smtpPort, String smtpChnl, String smtpAuth, String authId, String authPw)
	{
		String pString = "";

		try {
			service.setMailServer(smtpHost, smtpPort, smtpChnl, smtpAuth, authId, authPw);

			StringBuilder sb = new StringBuilder();
			sb.append("서버:" + smtpHost);
			sb.append(", 포트:" + smtpPort);
			sb.append(", 보안연결:");
			if (smtpChnl.equals("MES")) {
				sb.append("Exchange");
			}
			else {
				sb.append(smtpChnl);
			}
			sb.append(", 인증여부:" + smtpAuth);
			sb.append(", 인증이메일:" + authId);

			service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					adminid, "AN", "0", sb.toString());

			pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
		}
		catch (Exception e) {
			pString = "Error : 데이터 저장 오류";
			e.printStackTrace();
		}

		return pString;
	}

	public String getMailSend(String sCode)
	{
		String pString = "";

		try {
			ArrayList<Object> arraylist = service.getMailSend(sCode);

			List<String> key = new ArrayList<String>();
			key.add("sendYn");
			key.add("recipient");
			key.add("referrer");
			key.add("subject");
			key.add("content");

			pString = JsonUtil.jqgridPaser(key, arraylist);
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류";
			e.printStackTrace();
		}

		return pString;
	}

	public String setMailSend(String adminid, String code, String referrer, String subject, String content)
	{
		String pString = "";

		try {
			service.setMailSend(code, referrer, subject, content);

			StringBuilder sb = new StringBuilder();
			if (code.equals("MSND0000")) {
				sb.append("인증 기능 비활성화 알림");
			}
			else if (code.equals("MSND0001")) {
				sb.append("SSO모듈 무결성 검증 오류 알림");
			}
			else if (code.equals("MSND0002")) {
				sb.append("암호모듈 자가시험 오류 알림");
			}
			else if (code.equals("MSND0003")) {
				sb.append("감사정보 저장용량 임계치 초과 알림");
			}
			sb.append(", 참조자:" + referrer);
			sb.append(", 제목:" + subject);
			sb.append(", 내용:" + content);

			service.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					adminid, "AO", "0", sb.toString());

			pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
		}
		catch (Exception e) {
			pString = "Error : 데이터 저장 오류";
			e.printStackTrace();
		}

		return pString;
	}

	public String mailServerTest(String smtpHost, String smtpPort, String smtpChnl, String smtpAuth, String authId, String authPw)
	{
		String pString = "";

		try {
			MailService sendMail = new MailService();
			sendMail.sendTest(smtpHost, smtpPort, smtpChnl, smtpAuth, authId, authPw);

			pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
		}
		catch (Exception e) {
			pString = "Error : 메일 발송 테스트 오류";
			e.printStackTrace();
		}

		return pString;
	}

	public String mailSendTest(String referrer, String subject, String content)
	{
		String pString = "";

		try {
			ArrayList<Object> arraylist = service.getMailServer();
			MailVO mailInfo = (MailVO) arraylist.get(0);

			ArrayList<Object> emaillist = service.getAdminEmail();
			List<String> recipient = new ArrayList<String>();
			for (int i = 0; i < emaillist.size(); i++) {
				AdminVO al = (AdminVO) emaillist.get(i);
				recipient.add(al.getEmail());
			}

			List<String> ccList = new ArrayList<String>(Arrays.asList(referrer.split(";")));
			for (int i = 0; i < ccList.size(); i++) {
				if (!ccList.get(i).trim().equals("")) {
					int idx = recipient.indexOf(ccList.get(i).trim());
					if (idx == -1)
						recipient.add(ccList.get(i).trim());
				}
			}

			if (recipient.size() == 0) {
				return "Error : 메일 발송 테스트 오류 (등록 관리자 이메일 없음)";
			}

			MailService sendMail = new MailService(mailInfo);
			sendMail.sendTest(recipient, subject + " (테스트 발송)", content);

			pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
		}
		catch (Exception e) {
			pString = "Error : 메일 발송 테스트 오류";
			e.printStackTrace();
		}

		return pString;
	}

	public String getAuditInfo(String fdate, String tdate, String stype, String srslt, int fnum, int tnum)
	{
		String pString = "";

		try {
			int totalCnt = service.countAuditInfo(fdate, tdate, stype, srslt, fnum, tnum);

			ArrayList<Object> arraylist = service.getAuditInfo(fdate, tdate, stype, srslt, fnum, tnum);

			List<String> key = new ArrayList<String>();
			key.add("index");
			key.add("logDatetime");
			key.add("caseUser");
			key.add("caseType");
			key.add("caseResult");
			key.add("caseData");

			pString = JsonUtil.jqgridPaser(key, arraylist, totalCnt);
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류";
			e.printStackTrace();
		}

		return pString;
	}

	public String getExcelAuditInfo(String fdate, String tdate, String stype, String srslt, String adminid)
	{
		String pString = "";

		try {
			ArrayList<Object> arraylist = service.getExcelAuditInfo(fdate, tdate, stype, srslt);

			if (arraylist.size() > 0) {
				SSOConfig config = SSOConfig.getInstance();
				String filename = "auditlog_" + Util.getDateFormat("yyyyMMddHHmmss") + "_" +adminid + ".xls";
				String path_filename = config.getSsoHomepath() + "/down/" + filename;
				//filename = filename.replace('\\', '/');
				log.debug("### Excel: {}", path_filename);

				File file = new File(path_filename);

				if (!file.exists()) {
					file.createNewFile();
				}

				WritableWorkbook workbook = Workbook.createWorkbook(file);
				WritableSheet sheet = workbook.createSheet("Sheet1", 0);
				Label label;

				label = new Label(0, 0, "No");  sheet.addCell(label);
				label = new Label(1, 0, "일시");  sheet.addCell(label);
				label = new Label(2, 0, "주체");  sheet.addCell(label);
				label = new Label(3, 0, "사건");  sheet.addCell(label);
				label = new Label(4, 0, "결과");  sheet.addCell(label);
				label = new Label(5, 0, "상세");  sheet.addCell(label);

				for (int i = 0; i < arraylist.size(); i++) {
					AuditListVO audit = (AuditListVO) arraylist.get(i);

					label = new Label(0, i+1, audit.getIndex());  sheet.addCell(label);
					label = new Label(1, i+1, audit.getLogDate() + " " + audit.getLogTime());  sheet.addCell(label);
					label = new Label(2, i+1, audit.getCaseUser());  sheet.addCell(label);
					label = new Label(3, i+1, audit.getCaseType());  sheet.addCell(label);
					label = new Label(4, i+1, audit.getCaseResult());  sheet.addCell(label);
					label = new Label(5, i+1, audit.getCaseData());  sheet.addCell(label);
				}

				workbook.write();
				workbook.close();

				pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"" + filename + "\"}]}";
			}
			else {
				pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":-1,\"resultdata\":\"\"}]}";
			}
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류";
			e.printStackTrace();
		}

		return pString;
	}

	public String getServerList(int fnum, int tnum)
	{
		String pString = "";
		int totalCnt = 0;
		ArrayList<Object> totallist = new ArrayList<Object>();
		ArrayList<Object> arraylist = new ArrayList<Object>();

		try {
			MetadataRepository metaInstance = MetadataRepository.getInstance();

			if (metaInstance.isIDP()) {
				totalCnt++;
				ServerVO serverInfo = new ServerVO();
				serverInfo.setIndex(String.valueOf(totalCnt));
				serverInfo.setType("서버");
				serverInfo.setId(metaInstance.getIDPName());
				String location = ((Endpoint) metaInstance.getIDPDescriptor().getSingleSignOnServices().get(0)).getLocation();
				int idx = location.indexOf("sso/");
				if (idx > 0) {
					serverInfo.setUrl(location.substring(0, idx + 4) + "monitor.jsp");
				}
				totallist.add(serverInfo);
			}

			List<String> spList = metaInstance.getSPNames();
			for (int i = 0; i < spList.size(); i++) {
				totalCnt++;
				ServerVO serverInfo = new ServerVO();
				serverInfo.setIndex(String.valueOf(totalCnt));
				serverInfo.setType("에이전트");
				serverInfo.setId(spList.get(i));

				String location = ((Endpoint) metaInstance.getSPDescriptor(spList.get(i)).getAssertionConsumerServices().get(0)).getLocation();
				if (location.length() > 4) {
					String ext = location.substring(location.length() - 4);
					int idx = location.indexOf("sso/");
					if (idx > 0) {
						if (ext.equals(".asp"))
							serverInfo.setUrl(location.substring(0, idx + 4) + "monitor.asp");
						else if (ext.equals("aspx"))
							serverInfo.setUrl(location.substring(0, idx + 4) + "monitor.aspx");
						else if (ext.equals(".php"))
							serverInfo.setUrl(location.substring(0, idx + 4) + "monitor.php");
						else
							serverInfo.setUrl(location.substring(0, idx + 4) + "monitor.jsp");
					}
				}

				totallist.add(serverInfo);
			}

			totalCnt = totallist.size();

			for (int idx = (fnum - 1); idx < tnum; idx++) {
				if (idx >= totallist.size())
					break;

				arraylist.add(totallist.get(idx));
			}

			List<String> key = new ArrayList<String>();
			key.add("index");
			key.add("id");
			key.add("type");
			key.add("url");
			key.add("access");
			key.add("status");

			pString = JsonUtil.jqgridPaser(key, arraylist, totalCnt);
		}
		catch (Exception e) {
			pString = "Error : 데이터 조회 오류";
			e.printStackTrace();
		}

		return pString;
	}

	public String integrityIDPTestSync(String adminid, String detail)
	{
		String pString = "";

		SyncMonitor.startMonitor();
		SyncMonitor.sendIntegrityEvent(adminid, detail);

		pString = integrityIDPTest(adminid, detail);

		return pString;
	}

	public String integrityIDPTest(String adminid, String detail)
	{
		String pString = "";
		int rtn_status = 0;

		try {
			rtn_status = SSOCryptoApi.getInstance().cryptoIntegrity(adminid, detail);
			if (rtn_status != 0) {
				service.sendMail("MSND0002", Util.getDateFormat("yyyy-MM-dd  HH:mm:ss"), SSOConfig.getInstance().getServerName(), "");
				throw new Exception("암호모듈 자가검증 실패");
			}

			rtn_status = SSOCryptoApi.getInstance().ssoIntegrity(adminid, detail);
			if (rtn_status != 0) {
				service.sendMail("MSND0001", Util.getDateFormat("yyyy-MM-dd  HH:mm:ss"), SSOConfig.getInstance().getServerName(), "");
				throw new Exception("SSO모듈 무결성 검증 실패");
			}

			rtn_status = SSOCryptoApi.getInstance().ssoProcess(adminid, detail);
			if (rtn_status != 0) {
				service.sendMail("MSND0005", Util.getDateFormat("yyyy-MM-dd  HH:mm:ss"), SSOConfig.getInstance().getServerName(), "");
				throw new Exception("SSO 프로세스 확인 실패");
			}

			pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
		}
		catch (Exception e) {
			pString = "Error : 무결성 검증 실패";
		}

		return pString;
	}

	public void integritySelfTestSync()
	{
		SSOConfig config = SSOConfig.getInstance();

		SyncMonitor.startMonitor();
		SyncMonitor.sendIntegrityEvent(config.getServerName(), config.getServerName() + ", 서버 자가 테스트");

		integritySelfTest(config.getServerName(), config.getServerName() + ", 서버 자가 테스트");
	}

	public void integritySelfTest(String adminid, String detail)
	{
		try {
			SSOCryptoApi crypto = SSOCryptoApi.getInstance();

			crypto.cryptoIntegrity(adminid, detail);
			crypto.ssoIntegrity(adminid, detail);
			crypto.ssoProcess(adminid, detail);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	public int resetIntegrityFile()
	{
		int result = -1;

		try {
			result = service.setIntegrityFile();

			if (result == 0) {
				SSOConfig config = SSOConfig.getInstance();
				SSOCryptoApi crypto = SSOCryptoApi.getInstance();

				result = crypto.ssoIntegrity(config.getServerName(), config.getServerName() + ", 서버 자가 테스트");
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}

		return result;
	}

	public String integritySPTest(String spName, String surl, String adminid, String detail)
	{
		String pString = "";

		SSOConfig config = SSOConfig.getInstance();

		if (!config.isIntegrityAgentSend()) {
			return "Error : 에이전트 접속 불가";
		}

		try {
			JSONObject jData = new JSONObject();
			jData.put("ad", adminid);
			jData.put("dt", detail);

			String encData = null;

			if (spName.substring(spName.length() - 2).equals("_S")) {
				jData.put("xid", Util.generateUUID());

				encData = SSOCryptoApi.getInstance().encryptJsonObject(jData, spName);
			}
			else {
				jData.put("xfr", config.getServerName());
				jData.put("xto", spName);

				encData = SSOCryptoApi.getInstance().encryptHttpParam(spName, surl, jData);
			}

			StringBuilder param = new StringBuilder();
			param.append("ED=").append(URLEncoder.encode(encData, "UTF-8"));

			URL url = new URL(surl);

			if (surl.indexOf("https") >= 0) {
				TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager()
				{
					public java.security.cert.X509Certificate[] getAcceptedIssuers()
					{
						return null;
					}

					public void checkClientTrusted(java.security.cert.X509Certificate[] arg0, String arg1) throws CertificateException
					{
					}

					public void checkServerTrusted(java.security.cert.X509Certificate[] arg0, String arg1) throws CertificateException
					{
					}
				} };

				SSLContext sc = SSLContext.getInstance("SSL");
				sc.init(null, trustAllCerts, new java.security.SecureRandom());
				HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
				HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier()
				{
					public boolean verify(String hostname, javax.net.ssl.SSLSession sslSession)
					{
						return true;
					}
				});
			}

			HttpURLConnection urlConn = (HttpURLConnection) url.openConnection();
			urlConn.setRequestMethod("POST");
			urlConn.setDoOutput(true);
			urlConn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");

			try {
				OutputStream stream = urlConn.getOutputStream();
				stream.write(param.toString().getBytes("UTF-8"));
				stream.flush();
				stream.close();

				int rcode = urlConn.getResponseCode();
				if (rcode != 200) {
					service.setAuditInfo(adminid, "AD", "1", spName + ", " + detail + ", 에이전트 미구동 상태");
					service.sendMail("MSND0001", Util.getDateFormat("yyyy-MM-dd  HH:mm:ss"), spName, "");

					pString = "Error : 무결성 검증 오류(" + rcode + ")";
				}
				else {
					pString = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
				}
			}
			catch (Exception e) {
				service.setAuditInfo(adminid, "AD", "1", spName + ", " + detail + ", 에이전트 미구동 상태");
				service.sendMail("MSND0001", Util.getDateFormat("yyyy-MM-dd  HH:mm:ss"), spName, "");

				pString = "Error : 무결성 검증 오류";
				e.printStackTrace();
			}
		}
		catch (Exception e) {
			pString = "Error : 무결성 검증 오류";
			e.printStackTrace();
		}

		return pString;
	}

	public void integrityAllSPTest(String adminid, String detail)
	{
		SSOConfig config = SSOConfig.getInstance();

		if (!config.isIntegrityAgentSend()) {
			return;
		}

		List<String> urlList = new ArrayList<String>();

		try {
			MetadataRepository metaInstance = MetadataRepository.getInstance();
			List<String> spList = metaInstance.getSPNames();

			for (int i = 0; i < spList.size(); i++) {
				String location = ((Endpoint) metaInstance.getSPDescriptor(spList.get(i)).getSingleLogoutServices().get(0)).getLocation();
				if (location.length() > 4) {
					String ext = location.substring(location.length() - 4);
					int idx = location.indexOf("sso/");
					if (idx > 0) {
						if (ext.equals(".jsp"))
							urlList.add(location.substring(0, idx + 4) + "integrityTest.jsp");
					}
				}
			}

			for (int i = 0; i < urlList.size(); i++) {
				URL url = new URL(urlList.get(i));

				String aid = "";
				if (adminid.equals("system")) {
					aid = spList.get(i);
				}
				else {
					aid = adminid;
				}

				JSONObject jData = new JSONObject();
				jData.put("ad", aid);
				jData.put("dt", detail);

				String encData = null;

				if (spList.get(i).substring(spList.get(i).length() - 2).equals("_S")) {
					jData.put("xid", Util.generateUUID());

					encData = SSOCryptoApi.getInstance().encryptJsonObject(jData, spList.get(i));
				}
				else {
					jData.put("xfr", config.getServerName());
					jData.put("xto", spList.get(i));

					encData = SSOCryptoApi.getInstance().encryptHttpParam(spList.get(i), urlList.get(i), jData);
				}

				StringBuilder param = new StringBuilder();
				param.append("ED=").append(URLEncoder.encode(encData, "UTF-8"));

				if (urlList.get(i).indexOf("https") >= 0) {
					TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager()
					{
						public java.security.cert.X509Certificate[] getAcceptedIssuers()
						{
							return null;
						}

						public void checkClientTrusted(java.security.cert.X509Certificate[] arg0, String arg1) throws CertificateException
						{
						}

						public void checkServerTrusted(java.security.cert.X509Certificate[] arg0, String arg1) throws CertificateException
						{
						}
					} };

					SSLContext sc = SSLContext.getInstance("SSL");
					sc.init(null, trustAllCerts, new java.security.SecureRandom());
					HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
					HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier()
					{
						public boolean verify(String hostname, javax.net.ssl.SSLSession sslSession)
						{
							return true;
						}
					});
				}

				HttpURLConnection urlConn = (HttpURLConnection) url.openConnection();
				urlConn.setRequestMethod("POST");
				urlConn.setDoOutput(true);
				urlConn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");

				try {
					OutputStream stream = urlConn.getOutputStream();
					stream.write(param.toString().getBytes("UTF-8"));
					stream.flush();
					stream.close();

					int rcode = urlConn.getResponseCode();
					if (rcode != 200) {
						service.setAuditInfo(aid, "AD", "1", spList.get(i) + ", " + detail + ", 에이전트 미구동 상태");
						service.sendMail("MSND0001", Util.getDateFormat("yyyy-MM-dd  HH:mm:ss"), spList.get(i), "");
					}
				}
				catch (Exception e) {
					service.setAuditInfo(aid, "AD", "1", spList.get(i) + ", " + detail + ", 에이전트 미구동 상태");
					service.sendMail("MSND0001", Util.getDateFormat("yyyy-MM-dd  HH:mm:ss"), spList.get(i), "");
				}
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

}