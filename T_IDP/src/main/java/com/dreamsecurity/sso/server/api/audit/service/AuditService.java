package com.dreamsecurity.sso.server.api.audit.service;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;

import com.dreamsecurity.jcaos.util.FileUtil;
import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.api.audit.vo.AupyVO;
import com.dreamsecurity.sso.server.api.service.base.ServiceBase;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.crypto.CryptoApi;
import com.dreamsecurity.sso.server.crypto.CryptoApiFactory;
import com.dreamsecurity.sso.server.crypto.SSOCryptoApi;
import com.dreamsecurity.sso.server.util.Util;

public class AuditService extends ServiceBase
{
	private static Logger log = LoggerFactory.getLogger(AuditService.class);

	public AuditService()
	{
	}

	public Map<String, String> getStatusAudit() throws Exception
	{
		Map<String, String> result = auditDao.getStatusAudit();

		if ("LDAP".equalsIgnoreCase(repositoryType) &&
				SSOConfig.getInstance().getBoolean("object-pool.dbex(0)[@usable]")) {
			Map<String, String> usedRate = auditDbDao.getUsedRateAudit();
			result.put("USED_RATE", usedRate.get("USED_RATE"));
		}

		CryptoApi crypto = CryptoApiFactory.getCryptoApi();

		String decWarnlimit = new String(crypto.decryptByDEK(result.get("WARN_LIMIT")));
		String decVerifycycle = new String(crypto.decryptByDEK(result.get("VERIFY_CYCLE")));
		String decVerifypoint = new String(crypto.decryptByDEK(result.get("VERIFY_POINT")));

		result.put("WARN_LIMIT", decWarnlimit);
		result.put("VERIFY_CYCLE", decVerifycycle);
		result.put("VERIFY_POINT", decVerifypoint);

		return result;
	}

	public void setVerifyTimeAupy() throws Exception
	{
		auditDao.setVerifyTimeAupy();
	}

	public void setAuditInfo(String encType, String encData)
	{
		try {
			JSONObject jsonData = null;

			if (encType.equals("XM")) {
				jsonData = SSOCryptoApi.getInstance().decryptHttpParam(encData);
			}
			else {
				jsonData = SSOCryptoApi.getInstance().decryptJsonObject(encData);
			}

			String logDate = (String) jsonData.get("ld");
			String logTime = (String) jsonData.get("lt");
			String caseUser = (String) jsonData.get("cu");
			String caseType = (String) jsonData.get("ct");
			String caseResult = (String) jsonData.get("cr");
			String caseData = (String) jsonData.get("cd");
			String spName = (String) jsonData.get("xfr");

			String detailData = caseData.length() > 500 ? caseData.substring(0, 500) : caseData;

			setAuditInfo(logDate, logTime, caseUser, caseType, caseResult, detailData);

			// 암호키 분배
			int index = detailData.indexOf("시작");
			if (caseType.equals("AA") && index == 0) {
				setAuditInfo(logDate, logTime, caseUser, "AV", "0", SSOConfig.getInstance().getServerName());
			}

			// e-mail
			String mdate = "";
			if (logDate != null && logDate.length() == 8) {
				mdate  = logDate.substring(0, 4) + "-";
				mdate += logDate.substring(4, 6) + "-";
				mdate += logDate.substring(6) + "  ";
			}
			if (logTime != null && logTime.length() == 6) {
				mdate += logTime.substring(0, 2) + ":";
				mdate += logTime.substring(2, 4) + ":";
				mdate += logTime.substring(4);
			}

			if ((caseType.equals("AC") || caseType.equals("AD") || caseType.equals("BB")) && caseResult.equals("1")) {
				if (caseType.equals("AC")) {
					sendMail("MSND0002", mdate, spName, "");
				}
				if (caseType.equals("AD")) {
					sendMail("MSND0001", mdate, spName, "");
				}
				if (caseType.equals("BB")) {
					sendMail("MSND0005", mdate, spName, "");
				}
			}
		}
		catch (Exception e) {
			log.error(e.toString());
		}
	}

	public ArrayList<Object> getAupyInfo() throws Exception
	{
		ArrayList<Object> list = auditDao.getAupyInfo();

		CryptoApi crypto = CryptoApiFactory.getCryptoApi();

		for (int i = 0; i < list.size(); i++) {
			AupyVO aupy = (AupyVO) list.get(i);

			String decWarnlimit = new String(crypto.decryptByDEK(aupy.getWarnLimit()));
			String decVerifycycle = new String(crypto.decryptByDEK(aupy.getVerifyCycle()));
			String decVerifypoint = new String(crypto.decryptByDEK(aupy.getVerifyPoint()));

			aupy.setWarnLimit(decWarnlimit);
			aupy.setVerifyCycle(decVerifycycle);
			aupy.setVerifyPoint(decVerifypoint);
		}

		return list;
	}

	public void setAupyInfo(String warnlimit, String verifycycle, String verifypoint) throws Exception
	{
		CryptoApi crypto = CryptoApiFactory.getCryptoApi();
		String encWarnlimit = crypto.encryptByDEK(warnlimit);
		String encVerifycycle = crypto.encryptByDEK(verifycycle);
		String encVerifypoint = crypto.encryptByDEK(verifypoint);

		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("warnLimit", encWarnlimit);
		paramMap.put("verifyCycle", encVerifycycle);
		paramMap.put("verifyPoint", encVerifypoint);

		auditDao.setAupyInfo(paramMap);
	}

	public void setMailServer(String smtpHost, String smtpPort, String smtpChnl, String smtpAuth, String authId, String authPw) throws Exception
	{
		CryptoApi crypto = CryptoApiFactory.getCryptoApi();
		String encSmtpHost = "";
		String encSmtpPort = "";
		String encSmtpChnl = "";
		String encSmtpAuth = "";
		String encAuthId = "";
		String encAuthPw = "";

		if (!Util.isEmpty(smtpHost)) { encSmtpHost = crypto.encryptByDEK(smtpHost); }
		if (!Util.isEmpty(smtpPort)) { encSmtpPort = crypto.encryptByDEK(smtpPort); }
		if (!Util.isEmpty(smtpChnl)) { encSmtpChnl = crypto.encryptByDEK(smtpChnl); }
		if (!Util.isEmpty(smtpAuth)) { encSmtpAuth = crypto.encryptByDEK(smtpAuth); }
		if (!Util.isEmpty(authId)) { encAuthId = crypto.encryptByDEK(authId); }
		if (!Util.isEmpty(authPw)) { encAuthPw = crypto.encryptByDEK(authPw); }

		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("smtpHost", encSmtpHost);
		paramMap.put("smtpPort", encSmtpPort);
		paramMap.put("smtpChnl", encSmtpChnl);
		paramMap.put("smtpAuth", encSmtpAuth);
		paramMap.put("authId", encAuthId);
		paramMap.put("authPw", encAuthPw);

		auditDao.setMailServer(paramMap);
	}

	public void setMailSend(String code, String referrer, String subject, String content) throws Exception
	{
		CryptoApi crypto = CryptoApiFactory.getCryptoApi();
		String encReferrer = "";
		String encSubject = "";
		String encContent = "";

		if (!Util.isEmpty(referrer)) { encReferrer = crypto.encryptByDEK(referrer); }
		if (!Util.isEmpty(subject)) { encSubject = crypto.encryptByDEK(subject); }
		if (!Util.isEmpty(content)) { encContent = crypto.encryptByDEK(content); }

		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("code", code);
		paramMap.put("referrer", encReferrer);
		paramMap.put("subject", encSubject);
		paramMap.put("content", encContent);

		auditDao.setMailSend(paramMap);
	}

	public int countAuditInfo(String fdate, String tdate, String stype, String srslt, int fnum, int tnum) throws Exception
	{
		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("fdate", fdate);
		paramMap.put("tdate", tdate);
		paramMap.put("stype", stype);
		paramMap.put("srslt", srslt);
		paramMap.put("fnum", fnum);
		paramMap.put("tnum", tnum);

		int cnt = 0;

		if (auditDbDao == null) {
			cnt = auditDao.countAuditInfo(paramMap);
		}
		else {
			cnt = auditDbDao.countAuditInfo(paramMap);
		}

		return cnt;
	}

	public ArrayList<Object> getAuditInfo(String fdate, String tdate, String stype, String srslt, int fnum, int tnum) throws Exception
	{
		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("fdate", fdate);
		paramMap.put("tdate", tdate);
		paramMap.put("stype", stype);
		paramMap.put("srslt", srslt);
		paramMap.put("fnum", fnum);
		paramMap.put("tnum", tnum);

		ArrayList<Object> resultMap = null;

		if (auditDbDao == null) {
			resultMap = (ArrayList<Object>) auditDao.getAuditInfo(paramMap);
		}
		else {
			resultMap = (ArrayList<Object>) auditDbDao.getAuditInfo(paramMap);
		}

		return resultMap;
	}

	public ArrayList<Object> getExcelAuditInfo(String fdate, String tdate, String stype, String srslt) throws Exception
	{
		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("fdate", fdate);
		paramMap.put("tdate", tdate);
		paramMap.put("stype", stype);
		paramMap.put("srslt", srslt);

		ArrayList<Object> resultMap = null;

		if (auditDbDao == null) {
			resultMap = (ArrayList<Object>) auditDao.getExcelAuditInfo(paramMap);
		}
		else {
			resultMap = (ArrayList<Object>) auditDbDao.getExcelAuditInfo(paramMap);
		}

		return resultMap;
	}

	public ArrayList<String> getVerifyPathList()
	{
		BufferedReader br = null;
		ArrayList<String> pathList = new ArrayList<String>();

		try {
			String inFile = SSOConfig.getInstance().getHomePath("config/integrity.cfg");

			br = new BufferedReader(new FileReader(inFile));
			String line;

			while ((line = br.readLine()) != null) {
				line = line.trim();
				int index1 = line.indexOf("[");
				int index2 = line.indexOf("]");
				if (index1 == 0 && index2 > 0)
					pathList.add(line.substring(index1 + 1, index2));
            }

			Collections.sort(pathList, new Comparator<String>() {
				public int compare(String o1, String o2) {
					return o1.compareTo(o2);
				}
			});
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		finally {
			if (br != null) try { br.close(); } catch (IOException e) {}
		}

		return pathList;
	}

	public ArrayList<String> getVerifyFileList(String path)
	{
		BufferedReader br = null;
		ArrayList<String> fileList = new ArrayList<String>();

		try {
			String inFile = SSOConfig.getInstance().getHomePath("config/integrity.cfg");

			br = new BufferedReader(new FileReader(inFile));
			boolean bPath = false;
			String line;

			while ((line = br.readLine()) != null) {
				line = line.trim();
				if (Util.isEmpty(line)) continue;
				int index1 = line.indexOf("[");
				int index2 = line.indexOf("]");
				if (index1 == 0 && index2 > 0) {
					if (path.equals(line.substring(index1 + 1, index2)))
						bPath = true;
					else
						if (bPath) break;
				}
				else {
					if (bPath)
						fileList.add(line);
				}
            }

			Collections.sort(fileList, new Comparator<String>() {
				public int compare(String o1, String o2) {
					return o1.compareTo(o2);
				}
			});
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		finally {
			if (br != null) try { br.close(); } catch (IOException e) {}
		}

		return fileList;
	}

	public int setIntegrityFile()
	{
		BufferedWriter bw = null;

		try {
			SSOConfig config = SSOConfig.getInstance();
			SSOCryptoApi crypto = SSOCryptoApi.getInstance();
			StringBuilder out = new StringBuilder();

			ArrayList<String> pathList = getVerifyPathList();

			for (int i = 0; i < pathList.size(); i++) {
				if (out.length() != 0) { out.append("\n"); }
				out.append("[" + pathList.get(i) + "]\n");

				ArrayList<String> fileList = getVerifyFileList(pathList.get(i));

				for (int j = 0; j < fileList.size(); j++) {
					String file = fileList.get(j);
					int index = file.indexOf(";");
					if (index > -1) {
						file = file.substring(0, index);
					}

					String fullpathfile = "";
					int idxsso = pathList.get(i).indexOf("/sso");
					if (idxsso == 0) {
						fullpathfile = config.getSsoHomepath() + pathList.get(i).substring(4) + "/" + file;
					}
					else {
						fullpathfile = config.getHomePath() + pathList.get(i) + "/" + file;
					}

					byte[] fileByte = FileUtil.read(fullpathfile);
					if (fileByte == null || fileByte.length < 0) {
						throw new Exception(fileList.get(j) + " file is not exist.");
					}

					String hmac = crypto.hmac(fileByte);

					out.append(file + ";" + hmac + "\n");
				}
			}

			String outFile = config.getHomePath("config/integrity.cfg");
			bw = new BufferedWriter(new FileWriter(outFile));
			bw.write(out.toString());
			bw.flush();
			bw.close();

			String allhmac = crypto.hmac(out.toString().getBytes());

			outFile = config.getHomePath("config/integrity.cfg.hmac");
			bw = new BufferedWriter(new FileWriter(outFile));
			bw.write(allhmac + "\n");
			bw.flush();
			bw.close();
		}
		catch (Exception e) {
			e.printStackTrace();
			if (bw != null) try { bw.close(); } catch (IOException ie) {}
			return -1;
		}

		return 0;
	}

	public void setIntegrityJar()
	{
		BufferedWriter bw = null;

		try {
			SSOCryptoApi crypto = SSOCryptoApi.getInstance();

			String cryptopath = com.dreamsecurity.kcmv.jce.provider.MagicJCryptoProvider.class
					.getProtectionDomain().getCodeSource().getLocation().getPath() + ".hmac";

			String ssopath = com.dreamsecurity.sso.idp.crypto.api.MJCryptoApi.class
					.getProtectionDomain().getCodeSource().getLocation().getPath();

			if (!Util.isEmpty(ssopath) && ssopath.length() >= 4 && !ssopath.substring(ssopath.length() - 4).equalsIgnoreCase(".jar")) {
				ssopath = SSOConfig.getInstance().getHomePath("config/" + SSOConfig.getJarVersion() + ".jar");
			}

			String hmacPath = SSOConfig.getInstance().getHomePath("config/" + SSOConfig.getJarVersion() + ".jar.hmac");

			// crypto
			byte[] cryptofileByte = FileUtil.read(cryptopath);
			if (cryptofileByte == null || cryptofileByte.length < 0)
				throw new Exception(cryptopath + " file is not exist.");

			String cryptojarHmac = crypto.hmac(cryptofileByte);
			
			// sso
			byte[] fileByte = FileUtil.read(ssopath);
			if (fileByte == null || fileByte.length < 0)
				throw new Exception(ssopath + " file is not exist.");

			String jarHmac = crypto.hmac(fileByte);

			bw = new BufferedWriter(new FileWriter(hmacPath));
			bw.write(cryptojarHmac + "\n" + jarHmac);
			bw.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		finally {
			if (bw != null) try { bw.close(); } catch (IOException ie) {}
		}
	}

}