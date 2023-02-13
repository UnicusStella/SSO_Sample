package com.dreamsecurity.sso.server.api.admin.service;

import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.api.admin.service.base.AdminBase;
import com.dreamsecurity.sso.server.api.admin.vo.AdminVO;
import com.dreamsecurity.sso.server.api.admin.vo.AdpyVO;
import com.dreamsecurity.sso.server.api.admin.vo.UrpyVO;
import com.dreamsecurity.sso.server.common.MStatus;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.crypto.CryptoApi;
import com.dreamsecurity.sso.server.crypto.CryptoApiFactory;
import com.dreamsecurity.sso.server.exception.SSOException;
import com.dreamsecurity.sso.server.util.Util;

public class AdminService extends AdminBase
{
	private static Logger log = LoggerFactory.getLogger(AdminService.class);

	public Map<String,Object> adminLogin(String id, String pw, String ip, String br)
	{
		Map<String,Object> returnMap = null;

		//log.debug("### Admin ID = {}", id);
		//log.debug("### Admin IP = {}", ip);
		//log.debug("### Admin BR = {}", br);

		try {
			//CryptoApi crypto = CryptoApiFactory.getCryptoApi();
			//log.debug("### Admin IP = {}", crypto.encryptByDEK(ip));

			// 관리자 접속 IP 체크
			List<Object> ipList = adminDao.getAdminIpList();

			decryptAdminIP(ipList);
			boolean boolIp = false;

			for (int i = 0; i < ipList.size(); i++) {
				String validIp = ((AdminVO) ipList.get(i)).getIp();
				if (validIp.equals(ip))
					boolIp = true;
			}

			if (!boolIp) {
				setAuditInfo(id, "AB", "1", ip + ", 미인가 관리자 접속 IP");
				throw new SSOException(MStatus.ADMIN_IP_FAIL, "Admin IP Invalid");
			}

			Map<String, String> paramMap = new HashMap<String, String>();
			paramMap.put("id", id);

			Map<String, String> resultMap = adminDao.getAdminByID(paramMap);

			if (resultMap == null || resultMap.size() == 0) {
				// 존재하지 않는 관리자
				setAuditInfo(id, "AB", "1", ip + ", 미존재 관리자 아이디");
				throw new SSOException(MStatus.ADMIN_ID_NOT_EXIST, "Not Exist Admin Account");
			}

			decryptAdminInfo(resultMap);

			if (resultMap.get("STATUS").equals(FLAG_USER_STATUS_LOCKED)) {
				// 잠긴 관리자
				int interval = Integer.parseInt((String) resultMap.get("LOCK_INTERVAL"));
				String lockTime = (String) resultMap.get("LOCK_TIME");

				if (interval > 0 && !lockTime.equals("")) {
					SimpleDateFormat sdt = new SimpleDateFormat("yyyyMMddHHmmss");
					Date lockDate = sdt.parse(lockTime);
					Date curDate = new Date(System.currentTimeMillis());
					Calendar cal = Calendar.getInstance();
					cal.setTime(lockDate);
					cal.add(Calendar.MINUTE, interval);
					lockDate = cal.getTime();

					int compare = curDate.compareTo(lockDate);
					if (compare < 0) {
						setAuditInfo(id, "AB", "1", ip + ", 인증 비활성화 상태");
						throw new SSOException(MStatus.ADMIN_AUTH_FAIL, "Current Admin Account is Locking");
					}
					else {
						resultMap.put("STATUS", FLAG_USER_STATUS_ACTIVE);
						resultMap.put("PW_MISMATCH_COUNT", "0");
						resultMap.put("LOCK_TIME", "");

						paramMap.put("status", FLAG_USER_STATUS_ACTIVE);
						paramMap.put("lockTime", "");
						adminDao.setAdminStatus(paramMap);
					}
				}
				else {
					setAuditInfo(id, "AB", "1", ip + ", 인증 비활성화 상태");
					throw new SSOException(MStatus.ADMIN_AUTH_FAIL, "Current Admin Account is Locking");
				}
			}

			// 사용 중인 관리자
			if (resultMap.get("ADMN_TYPE").equals("S")) {
				List<AdminVO> resultList = adminDao.getUsingAdmin();
	
				for (int i = 0; i < resultList.size(); i++) {
					AdminVO admin = (AdminVO) resultList.get(i);
	
					if (!ip.equals(admin.getLoginIp()) || !br.equals(admin.getLoginBr())) {
						int interval = SSOConfig.getInstance().getDupAccessTime();
						String accessTime = admin.getAccessTime();
	
						if (interval > 0 && !Util.isEmpty(accessTime)) {
							SimpleDateFormat sdt = new SimpleDateFormat("yyyyMMddHHmmss");
							Date accessDate = sdt.parse(accessTime);
							Calendar cal = Calendar.getInstance();
							cal.setTime(accessDate);
							cal.add(Calendar.MINUTE, interval);
							accessDate = cal.getTime();
	
							Date curDate = new Date(System.currentTimeMillis());
	
							int compare = curDate.compareTo(accessDate);
							if (compare < 0) {
								setAuditInfo(id, "AB", "1", ip + ", 사용 중인 다른 관리자 있음");
								throw new SSOException(MStatus.ADMIN_ANOTHER_USING, "Using another Admin");
							}
						}
					}
				}
			}

			pw = hashCrypto.getSha256Hex(pw, resultMap.get("PW_UPDATE_TIME"));
			//log.debug("### hash = {}", pw);

			// 패스워드 체크
			if (!pw.equals(resultMap.get("PASSWORD"))) {
				int PWMismatchCount = Integer.parseInt((String) resultMap.get("PW_MISMATCH_COUNT"));
				int PWMismatchAllow = Integer.parseInt((String) resultMap.get("PW_MISMATCH_ALLOW"));

				if ((PWMismatchCount + 1) >= PWMismatchAllow) {
					// 패스워드 오류 회수 증가
					adminDao.setAdminPWMismatchCount(id, String.valueOf(PWMismatchAllow), FLAG_USER_STATUS_LOCKED);

					// 관리자 잠김 해제 시작
					int interval = Integer.parseInt((String) resultMap.get("LOCK_INTERVAL"));
					AdminUnlock adminunlock = new AdminUnlock(id, interval);
					new Thread(adminunlock).start();

					// 관리자 계정 잠김, 메일 발송
					sendMail("MSND0000", Util.getDateFormat("yyyy-MM-dd  HH:mm:ss"), "관리자", id);

					setAuditInfo(id, "AB", "1", ip + ", 패스워드 오류, 인증 비활성화 상태로 변경");
					throw new SSOException(MStatus.ADMIN_ID_LOCK, "Admin Account is now Locking");
				}
				else {
					// 패스워드 오류 회수 증가
					adminDao.setAdminPWMismatchCount(id, String.valueOf(PWMismatchCount + 1), FLAG_USER_STATUS_ACTIVE);

					// 패스워드 오류
					setAuditInfo(id, "AB", "1", ip + ", 패스워드 오류");
					throw new SSOException(MStatus.ADMIN_PW_NOT_MATCH, "Password mismatch");
				}
			}
			else {
				// 인증 성공
				setAuditInfo(id, "AB", "0", ip);
				returnMap = createAdminLoginMap(ip, br, resultMap);
			}
		}
		catch (SSOException e) {
			log.error("### 인증 실패 : adminId = {}", id);
			log.error("### adminLogin() SSOException: {}, {}", e.getErrorCode(), e.toString());
			returnMap = createAdminLoginMap(e.getErrorCode(), e.getMessage(), e.getDetailMessage());
		}
		catch (Exception e) {
			log.error("### 인증 오류 : adminId = {}", id);
			log.error("### adminLogin() Exception: {}", e.toString());
			returnMap = createAdminLoginMap(MStatus.ADMIN_AUTH_FAIL, e.getMessage(), "");
		}

		return returnMap;
	}

	public void decryptAdminIP(List<Object> list)
	{
		try {
			CryptoApi crypto = CryptoApiFactory.getCryptoApi();

			for (int i = 0; i < list.size(); i++) {
				AdminVO admin = (AdminVO) list.get(i);
				String decIp = new String(crypto.decryptByDEK(admin.getIp()));
				admin.setIp(decIp);
			}
		}
		catch (Exception e) {
			log.error("### decryptAdminIP() Exception: {}", e.toString());
		}
	}

	public void decryptAdminInfo(Map<String, String> resultMap)
	{
		try {
			CryptoApi crypto = CryptoApiFactory.getCryptoApi();

			if (!"0".equals(resultMap.get("PW_MISMATCH_ALLOW"))) {
				resultMap.put("PW_MISMATCH_ALLOW", new String(crypto.decryptByDEK(resultMap.get("PW_MISMATCH_ALLOW"))));
			}

			if (!"0".equals(resultMap.get("SESSION_TIME"))) {
				resultMap.put("SESSION_TIME", new String(crypto.decryptByDEK(resultMap.get("SESSION_TIME"))));
			}

			if (!"0".equals(resultMap.get("LOCK_INTERVAL"))) {
				resultMap.put("LOCK_INTERVAL", new String(crypto.decryptByDEK(resultMap.get("LOCK_INTERVAL"))));
			}
		}
		catch (Exception e) {
			log.error("### decryptAdminInfo() Exception: {}", e.toString());
		}
	}

	private Map<String, Object> createAdminLoginMap(String ip, String br, Map<String, String> resultMap) throws SSOException, Exception
	{
		Map<String, Object> returnMap = new HashMap<String, Object>();
		returnMap.put("code", MStatus.SUCCESS);
		returnMap.put("message", "");
		returnMap.put("detail", "");
		returnMap.put("id", (String) resultMap.get("ID"));
		returnMap.put("name", (String) resultMap.get("NAME"));
		returnMap.put("admnIp", ip);
		returnMap.put("admnType", (String) resultMap.get("ADMN_TYPE"));
		returnMap.put("admnMenu", resultMap.get("MENU_CODE") == null ? "" : (String) resultMap.get("MENU_CODE"));
		returnMap.put("admnFirst", resultMap.get("FIRST_YN") == null ? "" : (String) resultMap.get("FIRST_YN"));
		returnMap.put("admnSalt", resultMap.get("PW_UPDATE_TIME") == null ? "" : (String) resultMap.get("PW_UPDATE_TIME"));
		returnMap.put("sessionTime", (String) resultMap.get("SESSION_TIME"));

		adminDao.setAdminAccessInfo(resultMap.get("ID"), ip, br, resultMap.get("ADMN_TYPE"));

		return returnMap;
	}

	private Map<String, Object> createAdminLoginMap(int code, String message, String detail)
	{
		Map<String, Object> returnMap = new HashMap<String, Object>();
		returnMap.put("code", code);
		returnMap.put("message", message);
		returnMap.put("detail", detail);

		return returnMap;
	}

	public void setAdminLogoutInfo(String id, String tp)
	{
		try {
			if (tp.equals("S")) {
				adminDao.setAdminUseYn();
			}

			adminDao.setAdminLogoutInfo(id);
		}
		catch (SQLException e) {
			log.error("### setAdminLogoutInfo() SQLException: {}, {}", e.getErrorCode(), e.toString());
		}
	}

	@SuppressWarnings("unchecked")
	public int setAdminPwd(HttpServletRequest request, String id, String curPwd, String newPwd, String adminsalt, String adminfirst)
	{
		try {
			String frPwd = hashCrypto.getSha256Hex(curPwd, adminsalt);

			String curTime = Util.getDateFormat("yyyyMMddHHmmss");
			String toPwd = hashCrypto.getSha256Hex(newPwd, curTime);

			Map<String, String> paramMap = new HashMap<String, String>();
			paramMap.put("id", id);
			paramMap.put("curPwd", frPwd);
			paramMap.put("newPwd", toPwd);
			paramMap.put("update", curTime);

			int cnt = adminDao.setAdminPwd(paramMap);

			if (cnt > 0) {
				if (adminfirst.equals("Y")) {
					adminDao.setAdminFirstYn(id);
				}

				HttpSession session = request.getSession(false);
				Map<String, Object> adminMap = (Map<String, Object>) session.getAttribute("SSO_ADMIN_INFO");
				if (adminMap != null) {
					adminMap.put("admnFirst", "");
					adminMap.put("admnSalt", curTime);
				}
			}

			return cnt;
		}
		catch (SQLException e) {
			log.error("### setAdminPwd() SQLException: {}, {}", e.getErrorCode(), e.toString());
		}

		return 0;
	}

	public List<Object> getAdminList() throws Exception
	{
		return adminDao.getAdminList();
	}

	public List<Object> getAdminInfo(String id) throws Exception
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("id", id);

		return adminDao.getAdminInfo(paramMap);
	}

	public void setAdminInfo(String newflag, String id, String name, String pwd, String type, String email, String menucode) throws Exception
	{
		String curTime = "";

		if (!Util.isEmpty(pwd)) {
			curTime = Util.getDateFormat("yyyyMMddHHmmss");
			pwd = hashCrypto.getSha256Hex(pwd, curTime);
		}

		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("newflag", newflag);
		paramMap.put("id", id);
		paramMap.put("name", name);
		paramMap.put("pwd", pwd);
		paramMap.put("update", curTime);
		paramMap.put("type", type);
		paramMap.put("email", email);
		paramMap.put("menucode", menucode);

		adminDao.setAdminInfo(paramMap);
	}

	public void removeAdminInfo(String uid) throws Exception
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("id", uid);

		adminDao.removeAdminInfo(paramMap);
	}

	public List<Object> getAdpyInfo(String code) throws Exception
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("code", code);

		List<Object> list = adminDao.getAdpyInfo(paramMap);

		CryptoApi crypto = CryptoApiFactory.getCryptoApi();

		for (int i = 0; i < list.size(); i++) {
			AdpyVO adpy = (AdpyVO) list.get(i);

			String decPwallow = new String(crypto.decryptByDEK(adpy.getPwMismatchAllow()));
			String decLocktime = new String(crypto.decryptByDEK(adpy.getLockTime()));
			String decSesstime = new String(crypto.decryptByDEK(adpy.getSessionTime()));
			String decIpcnt = new String(crypto.decryptByDEK(adpy.getIpMaxCount()));

			adpy.setPwMismatchAllow(decPwallow);
			adpy.setLockTime(decLocktime);
			adpy.setSessionTime(decSesstime);
			adpy.setIpMaxCount(decIpcnt);
		}

		return list;
	}

	public void setAdpyInfo(String code, String pwallow, String locktime, String sesstime, String ipcnt) throws Exception
	{
		CryptoApi crypto = CryptoApiFactory.getCryptoApi();
		String encPwallow = crypto.encryptByDEK(pwallow);
		String encLocktime = crypto.encryptByDEK(locktime);
		String encSesstime = crypto.encryptByDEK(sesstime);
		String encIpcnt = crypto.encryptByDEK(ipcnt);

		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("code", code);
		paramMap.put("pwallow", encPwallow);
		paramMap.put("locktime", encLocktime);
		paramMap.put("sesstime", encSesstime);
		paramMap.put("ipcnt", encIpcnt);

		adminDao.setAdpyInfo(paramMap);
	}

	public List<Object> getAdminIpList() throws Exception
	{
		List<Object> list = adminDao.getAdminIpList();

		CryptoApi crypto = CryptoApiFactory.getCryptoApi();

		for (int i = 0; i < list.size(); i++) {
			AdminVO admin = (AdminVO) list.get(i);
			String decIp = new String(crypto.decryptByDEK(admin.getIp()));
			admin.setIp(decIp);
		}

		return list;
	}

	public void setAdminIp(String ip) throws Exception
	{
		CryptoApi crypto = CryptoApiFactory.getCryptoApi();
		String encIp = crypto.encryptByDEK(ip);

		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("ip", encIp);

		adminDao.setAdminIp(paramMap);
	}

	public void removeAdminIp(String ip) throws Exception
	{
		CryptoApi crypto = CryptoApiFactory.getCryptoApi();
		String encIp = crypto.encryptByDEK(ip);

		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("ip", encIp);

		adminDao.removeAdminIp(paramMap);
	}

	public int countUserListByVal(String sType, String sValue) throws Exception
	{
		Map<String, String> paramMap = new HashMap<String, String>();

		if (sType.equals("1"))
			paramMap.put("userName", sValue);
		else
			paramMap.put("userId", sValue);

		int cnt = adminDao.countUserListByVal(paramMap);

		return cnt;
	}

	public List<Object> getUserListByVal(String sType, String sValue, int fnum, int tnum) throws Exception
	{
		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("fnum", fnum);
		paramMap.put("tnum", tnum);

		if (sType.equals("1"))
			paramMap.put("userName", sValue);
		else
			paramMap.put("userId", sValue);

		List<Object> resultMap = adminDao.getUserListByVal(paramMap);

		return resultMap;
	}

	public int getUserRowByVal(String sType, String sValue) throws Exception
	{
		Map<String, String> paramMap = new HashMap<String, String>();

		if (sType.equals("1"))
			paramMap.put("userName", sValue);
		else
			paramMap.put("userId", sValue);

		return adminDao.getUserRowByVal(paramMap);
	}

	public void setUserUnlock(String userId) throws Exception
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("userId", userId);

		adminDao.setUserUnlock(paramMap);
	}

	public void setAdminUnlock(String id) throws Exception
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("id", id);
		paramMap.put("status", FLAG_USER_STATUS_ACTIVE);
		paramMap.put("lockTime", "");

		adminDao.setAdminStatus(paramMap);

		setAuditInfo(SSOConfig.getInstance().getServerName(), "AQ", "0", "관리자:" + id);
	}

	public List<Object> getUrpyInfo(String code) throws Exception
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("code", code);

		List<Object> list = adminDao.getUrpyInfo(paramMap);

		CryptoApi crypto = CryptoApiFactory.getCryptoApi();

		for (int i = 0; i < list.size(); i++) {
			UrpyVO urpy = (UrpyVO) list.get(i);

			String decPwMismatchAllow = new String(crypto.decryptByDEK(urpy.getPwMismatchAllow()));
			String decPwChangeWarn = new String(crypto.decryptByDEK(urpy.getPwChangeWarn()));
			String decPwValidate = new String(crypto.decryptByDEK(urpy.getPwValidate()));
			String decPollingTime = new String(crypto.decryptByDEK(urpy.getPollingTime()));
			String decSessionTime = new String(crypto.decryptByDEK(urpy.getSessionTime()));

			urpy.setPwMismatchAllow(decPwMismatchAllow);
			urpy.setPwChangeWarn(decPwChangeWarn);
			urpy.setPwValidate(decPwValidate);
			urpy.setPollingTime(decPollingTime);
			urpy.setSessionTime(decSessionTime);
		}

		return list;
	}

	public void setUrpyInfo(String ucode, String pwcnt, String pwwarn, String pwvalid,
			String polltime, String sesstime) throws Exception
	{
		CryptoApi crypto = CryptoApiFactory.getCryptoApi();
		String encPwcnt = crypto.encryptByDEK(pwcnt);
		String encPwwarn = crypto.encryptByDEK(pwwarn);
		String encPwvalid = crypto.encryptByDEK(pwvalid);
		String encPolltime = crypto.encryptByDEK(polltime);
		String encSesstime = crypto.encryptByDEK(sesstime);

		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("code", ucode);
		paramMap.put("pwcnt", encPwcnt);
		paramMap.put("pwwarn", encPwwarn);
		paramMap.put("pwvalid", encPwvalid);
		paramMap.put("polltime", encPolltime);
		paramMap.put("sesstime", encSesstime);

		adminDao.setUrpyInfo(paramMap);
	}

	public int countUserList() throws Exception
	{
		return adminDao.countUserList();
	}

	public ArrayList<Object> getUserList(int fnum, int tnum) throws Exception
	{
		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("fnum", fnum);
		paramMap.put("tnum", tnum);

		return adminDao.getUserList(paramMap);
	}

	public int countUserLockedList() throws Exception
	{
		return adminDao.countUserLockedList();
	}

	public ArrayList<Object> getUserLockedList(int fnum, int tnum) throws Exception
	{
		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("fnum", fnum);
		paramMap.put("tnum", tnum);

		return adminDao.getUserLockedList(paramMap);
	}

	public List<Object> getUserInfo(String id) throws Exception
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("id", id);

		return adminDao.getUserInfo(paramMap);
	}

	public void setUserInfo(String newflag, String id, String name, String pwd) throws Exception
	{
		String curTime = "";

		if (!Util.isEmpty(pwd)) {
			curTime = Util.getDateFormat("yyyyMMddHHmmss");
			pwd = hashCrypto.getHashWithSalt(pwd, curTime);
		}

		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("newflag", newflag);
		paramMap.put("id", id);
		paramMap.put("name", name);
		paramMap.put("pwd", pwd);
		paramMap.put("update", curTime);

		adminDao.setUserInfo(paramMap);
	}

	public void removeUserInfo(String uid) throws Exception
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("id", uid);

		adminDao.removeUserInfo(paramMap);
	}

	public int countUserAccessInfo(String uid, String fdate, String tdate, String stype) throws Exception
	{
		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("userId", uid);
		paramMap.put("fdate", fdate);
		paramMap.put("tdate", tdate);
		paramMap.put("stype", stype);

		int cnt = 0;

		if (adminDbDao == null) {
			cnt = adminDao.countUserAccessInfo(paramMap);
		}
		else {
			cnt = adminDbDao.countUserAccessInfo(paramMap);
		}

		return cnt;
	}

	public ArrayList<Object> getUserAccessInfo(String uid, String fdate, String tdate, String stype, int fnum, int tnum) throws Exception
	{
		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("userId", uid);
		paramMap.put("fdate", fdate);
		paramMap.put("tdate", tdate);
		paramMap.put("stype", stype);
		paramMap.put("fnum", fnum);
		paramMap.put("tnum", tnum);

		ArrayList<Object> resultMap = null;

		if (adminDbDao == null) {
			resultMap = (ArrayList<Object>) adminDao.getUserAccessInfo(paramMap);
		}
		else {
			resultMap = (ArrayList<Object>) adminDbDao.getUserAccessInfo(paramMap);
		}

		return resultMap;
	}

	public ArrayList<Object> getExcelAccessInfo(String uid, String fdate, String tdate, String stype) throws Exception
	{
		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("userId", uid);
		paramMap.put("fdate", fdate);
		paramMap.put("tdate", tdate);
		paramMap.put("stype", stype);

		ArrayList<Object> resultMap = null;

		if (adminDbDao == null) {
			resultMap = (ArrayList<Object>) adminDao.getExcelAccessInfo(paramMap);
		}
		else {
			resultMap = (ArrayList<Object>) adminDbDao.getExcelAccessInfo(paramMap);
		}

		return resultMap;
	}

	public ArrayList<Object> getStatsDateAccessInfo(String sdate) throws Exception
	{
		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("sdate", sdate);

		ArrayList<Object> resultMap = null;

		if (adminDbDao == null) {
			resultMap = (ArrayList<Object>) adminDao.getStatsDateAccessInfo(paramMap);
		}
		else {
			resultMap = (ArrayList<Object>) adminDbDao.getStatsDateAccessInfo(paramMap);
		}

		return resultMap;
	}

	public ArrayList<Object> getStatsMonthAccessInfo(String sdate) throws Exception
	{
		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("sdate", sdate);

		ArrayList<Object> resultMap = null;

		if (adminDbDao == null) {
			resultMap = (ArrayList<Object>) adminDao.getStatsMonthAccessInfo(paramMap);
		}
		else {
			resultMap = (ArrayList<Object>) adminDbDao.getStatsMonthAccessInfo(paramMap);
		}

		return resultMap;
	}

	public ArrayList<Object> getStatsYearAccessInfo(String sdate) throws Exception
	{
		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("sdate", sdate);

		ArrayList<Object> resultMap = null;

		if (adminDbDao == null) {
			resultMap = (ArrayList<Object>) adminDao.getStatsYearAccessInfo(paramMap);
		}
		else {
			resultMap = (ArrayList<Object>) adminDbDao.getStatsYearAccessInfo(paramMap);
		}

		return resultMap;
	}

	public List<Object> getClientList() throws Exception
	{
		return adminDao.getClientList();
	}
	
	public List<Object> getClientInfo(String id) throws Exception
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("id", id);

		return adminDao.getClientInfo(paramMap);
	}
	
	public List<Object> getClientRedirect(String id) throws Exception
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("id", id);

		return adminDao.getClientRedirect(paramMap);
	}
	
	public List<Object> listClientRedirect(String id) throws Exception
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("id", id);

		return adminDao.listClientRedirect(paramMap);
	}

	public List<Object> getClientScope(String id) throws Exception
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("id", id);

		return adminDao.getClientScope(paramMap);
	}

	public List<Object> listClientScope(String client) throws Exception
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("id", client);

		return adminDao.listClientScope(paramMap);
	}

	public List<Object> getScopeList() throws Exception
	{
		return adminDao.getScopeList();
	}
	
	public void removeClient(String id) throws Exception
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("id", id);

		adminDao.removeClient(paramMap);
	}
	
	public void setClientInfo(String newflag, String id, String name, String protocol, String enabled, String nonce, String pkce,
			String refresh, String secret, String tokenLife, String refreshLife,
			String codeLife, String grantType, String responseType, String[] scopeList, String[] redirectUriList) throws Exception
	{
		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("newflag", newflag);
		paramMap.put("id", id);
		paramMap.put("name", name);
		paramMap.put("protocol", protocol);
		paramMap.put("enabled", enabled);
		paramMap.put("redirectUriList", redirectUriList);

		if (protocol.equals("OIDC")) {
			paramMap.put("secret", secret);
			paramMap.put("nonce", nonce);
			paramMap.put("pkce", pkce);
			paramMap.put("refresh", refresh);
			paramMap.put("codeLife", codeLife);
			paramMap.put("tokenLife", tokenLife);
			paramMap.put("refreshLife", refreshLife);
			paramMap.put("responseType", responseType);
			paramMap.put("grantType", grantType);
			paramMap.put("scopeList", scopeList);
		}

		adminDao.setClientInfo(paramMap);
	}
	
	public void removeScope(String id) throws Exception
	{
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("id", id);

		adminDao.removeScope(paramMap);
	}
	
	public void setScope(String id) throws Exception
	{
		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("id", id);
	
		adminDao.setScope(paramMap);
	}

	public void setUserChangePwd(String id, String name, String pwd) throws Exception
	{
		String curTime = "";

		if (!Util.isEmpty(pwd)) {
			curTime = Util.getDateFormat("yyyyMMddHHmmss");
			pwd = hashCrypto.getHashWithSalt(pwd, curTime);
		}

		Map<String, String> paramMap = new HashMap<String, String>();

		paramMap.put("id", id);
		paramMap.put("name", name);
		paramMap.put("pwd", pwd);
		paramMap.put("update", curTime);

		adminDao.setUserChangePwd(paramMap);
	}

}