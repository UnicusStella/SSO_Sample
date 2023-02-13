package com.dreamsecurity.sso.server.api.user.service;

import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.api.user.service.base.UserBase;
import com.dreamsecurity.sso.server.common.MStatus;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.crypto.CryptoApi;
import com.dreamsecurity.sso.server.crypto.CryptoApiFactory;
import com.dreamsecurity.sso.server.crypto.SSOCryptoApi;
import com.dreamsecurity.sso.server.dup.DupClient;
import com.dreamsecurity.sso.server.exception.SSOException;
import com.dreamsecurity.sso.server.util.Util;

public class UserService extends UserBase
{
	private static Logger log = LoggerFactory.getLogger(UserService.class);

	public int connectTest()
	{
		try {
			Map<String, String> resultMap = userDao.getStatus();

			if (resultMap == null || resultMap.size() == 0) {
				return MStatus.FAIL;
			}

			if (userDbDao != null) {
				resultMap = null;
				resultMap = userDbDao.getStatus();

				if (resultMap == null || resultMap.size() == 0) {
					return MStatus.FAIL;
				}
			}

			return MStatus.SUCCESS;
		}
		catch (SQLException e) {
			e.printStackTrace();
		}

		return MStatus.FAIL;
	}

	public JSONObject login(String userId, String userPw, String userIp, String userBr, String spName, String loginType)
	{
		JSONObject result = null;
		SSOConfig config = SSOConfig.getInstance();

		readyAccessLog("", "", "", "", "", "");

		try {
			Map<String, String> paramMap = new HashMap<String, String>();
			paramMap.put("userId", userId);

			Map<String, String> resultMap = userDao.getUserByID(paramMap);

			if (resultMap == null || resultMap.size() == 0) {
				// 존재하지 않는 사용자
				setAuditInfo(userId, "AG", "1", userIp + ", 미존재 사용자 아이디, " + spName);
				readyAccessLog(userId, userIp, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_ID_MISMATCH);
				throw new SSOException(MStatus.USER_ID_NOT_EXIST, MStatus.MSG_USER_ID_NOT_EXIST);
			}

			decryptUserInfo(resultMap);

			if (FLAG_USER_STATUS_LOCKED.equals(resultMap.get("USER_STATUS"))) {
				// 잠긴 사용자
				int interval = config.getInt("user.autounlock.time", 0);
				String accessTime = resultMap.get("ACCESS_TIME") == null ? "" : resultMap.get("ACCESS_TIME");

				if (interval > 0 && !Util.isEmpty(accessTime)) {					
					// ACCESS_TIME 비교
					SimpleDateFormat sdt = new SimpleDateFormat("yyyyMMddHHmmss");
					Date accessDate = sdt.parse(accessTime);
					Calendar cal = Calendar.getInstance();
					cal.setTime(accessDate);
					cal.add(Calendar.MINUTE, interval);
					accessDate = cal.getTime();

					Date curDate = new Date(System.currentTimeMillis());

					int compare = curDate.compareTo(accessDate);
					
					if (compare < 0) {
						setAuditInfo(userId, "AG", "1", userIp + ", 인증 비활성화 상태, " + spName);
						readyAccessLog(userId, userIp, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_LOCK);
						throw new SSOException(MStatus.USER_ID_LOCK, MStatus.MSG_USER_ID_LOCK);
					}
				}
				else {
					setAuditInfo(userId, "AG", "1", userIp + ", 인증 비활성화 상태, " + spName);
					readyAccessLog(userId, userIp, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_LOCK);
					throw new SSOException(MStatus.USER_ID_LOCK, MStatus.MSG_USER_ID_LOCK);
				}
			}
			else if (FLAG_USER_STATUS_RETIREMENT.equals(resultMap.get("USER_STATUS"))) {
				// 퇴직 사용자
				setAuditInfo(userId, "AG", "1", userIp + ", 퇴직 사용자, " + spName);
				readyAccessLog(userId, userIp, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_RETIRE);
				throw new SSOException(MStatus.USER_ID_RETIREMENT, MStatus.MSG_USER_ID_RETIREMENT);
			}
			else {
			}

			if (config.getDupLoginType() == 1) {
				// 선입자우선 중복로그인 방지
				String loginedIp = resultMap.get("NOW_LOGIN_IP") == null ? "" : resultMap.get("NOW_LOGIN_IP");
				String loginedBr = resultMap.get("NOW_LOGIN_BR") == null ? "" : resultMap.get("NOW_LOGIN_BR");
				String accessTime = resultMap.get("ACCESS_TIME") == null ? "" : resultMap.get("ACCESS_TIME");
				int interval = config.getDupAccessTime();
				
				if (!Util.isEmpty(loginedIp) && !userIp.equals(loginedIp)) {
					// IP 다르면 로그인 불가
					if (interval > 0 && !Util.isEmpty(accessTime)) {
						// ACCESS_TIME 비교
						SimpleDateFormat sdt = new SimpleDateFormat("yyyyMMddHHmmss");
						Date accessDate = sdt.parse(accessTime);
						Calendar cal = Calendar.getInstance();
						cal.setTime(accessDate);
						cal.add(Calendar.MINUTE, interval);
						accessDate = cal.getTime();

						Date curDate = new Date(System.currentTimeMillis());

						int compare = curDate.compareTo(accessDate);
						if (compare < 0) {
							setAuditInfo(userId, "AG", "1", userIp + ", " + spName + ", 다른 자리에서 로그인 중인 사용자");
							readyAccessLog(userId, userIp, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_DUP_LOGIN);
							throw new SSOException(MStatus.USER_DUP_LOGIN, "The user account is already logged in");
						}
					}
				}
				else if (!Util.isEmpty(loginedIp) && userIp.equals(loginedIp)) {
					// IP 같고, 브라우저 다르면 로그인 불가
					if (config.getDupBrowser()) {
						if (!Util.isEmpty(loginedBr) && !userBr.equals(loginedBr)) {
							if (interval > 0 && !Util.isEmpty(accessTime)) {
								// ACCESS_TIME 비교
								SimpleDateFormat sdt = new SimpleDateFormat("yyyyMMddHHmmss");
								Date accessDate = sdt.parse(accessTime);
								Calendar cal = Calendar.getInstance();
								cal.setTime(accessDate);
								cal.add(Calendar.MINUTE, interval);
								accessDate = cal.getTime();

								Date curDate = new Date(System.currentTimeMillis());

								int compare = curDate.compareTo(accessDate);
								if (compare < 0) {
									setAuditInfo(userId, "AG", "1", userIp + ", " + userBr + ", " + spName + ", 다른 자리에서 로그인 중인 사용자");
									readyAccessLog(userId, userIp, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_DUP_LOGIN);
									throw new SSOException(MStatus.USER_DUP_LOGIN, "The user account is already logged in");
								}
							}
						}
					}
				}
			}

			// 패스워드 검사
			if (!FLAG_FUNC_CERT0005.equals(userPw)) {
				userPw = hashCrypto.getHashWithSalt(userPw, resultMap.get("PW_UPDATE_TIME"));
				//log.debug("### hash = " + userPw);

				if (!userPw.equals(resultMap.get("USER_PASSWORD"))) {
					if (FLAG_USER_STATUS_LOCKED.equals(resultMap.get("USER_STATUS"))) {
						// 잠긴 사용자
						setAuditInfo(userId, "AG", "1", userIp + ", 인증 비활성화 상태, " + spName);
						readyAccessLog(userId, userIp, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_LOCK);
						throw new SSOException(MStatus.USER_ID_LOCK, MStatus.MSG_USER_ID_LOCK);
					}
					else {
						int PWMismatchCount = Integer.parseInt((String) resultMap.get("PW_MISMATCH_COUNT"));
						int PWMismatchAllow = Integer.parseInt((String) resultMap.get("PW_MISMATCH_ALLOW"));

						if ((PWMismatchCount + 1) >= PWMismatchAllow) {
							// 패스워드 오류 회수 증가
							userDao.setPWMismatchCount(userId, String.valueOf(PWMismatchAllow), FLAG_USER_STATUS_LOCKED);

							// 사용자 계정 잠김, 메일 발송
							sendMail("MSND0000", Util.getDateFormat("yyyy-MM-dd  HH:mm:ss"), "사용자", userId);

							setAuditInfo(userId, "AG", "1", userIp + ", 패스워드 오류, 인증 비활성화 상태로 변경, " + spName);
							readyAccessLog(userId, userIp, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_LOCK);
							throw new SSOException(MStatus.USER_ID_LOCK, "User Account is now Locking");
						}
						else {
							// 패스워드 오류 회수 증가
							userDao.setPWMismatchCount(userId, String.valueOf(PWMismatchCount + 1), FLAG_USER_STATUS_ACTIVE);

							String countInfo = (PWMismatchCount + 1) + ">" + PWMismatchAllow;

							// 패스워드 오류
							setAuditInfo(userId, "AG", "1", userIp + ", 패스워드 오류, " + spName);
							readyAccessLog(userId, userIp, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_PW_MISMATCH);
							throw new SSOException(MStatus.USER_PW_NOT_MATCH, "Password mismatch. left try count: "
									+ (PWMismatchAllow - PWMismatchCount - 1), countInfo);
						}
					}
				}
				else {
					setAuditInfo(userId, "AG", "0", userIp + ", " + spName);
					readyAccessLog(userId, userIp, TYPE_IDPW_LOGIN, spName, userBr, TYPE_SUCCESS);
					result = createLoginMessage(resultMap, userIp, userBr, loginType);
				}
			}
			else {
				setAuditInfo(userId, "AG", "0", userIp + ", " + spName);
				readyAccessLog(userId, userIp, TYPE_ID_LOGIN, spName, userBr, TYPE_SUCCESS);
				result = createLoginMessage(resultMap, userIp, userBr, "ID_NOPW");
			}
		}
		catch (SSOException e) {
			log.error("### 인증 실패: {}, {}", userId, e.getMessage());
			result = createResult(e.getErrorCode(), e.getMessage(), e.getDetailMessage());
		}
		catch (Exception e) {
			log.error("### 인증 오류: {}, {}", userId, e.getMessage());
			result = createResult(MStatus.ETC_AUTH_FAIL, e.getMessage());
		}

		return result;
	}

	public JSONObject loginCert(String signedData, String userIp, String userBr, String spName, String loginType)
	{
		JSONObject result = null;
		SSOConfig config = SSOConfig.getInstance();
		String userDn = "";

		readyAccessLog("", "", "", "", "", "");

		try {
			Map<String,Object> signedDataInfo = new HashMap<String,Object>();
			String content = SSOCryptoApi.getInstance().procSignedData(signedData, signedDataInfo);
			userDn = (String) signedDataInfo.get("dn");

			if (config.getCertValueType().equalsIgnoreCase("cn")) {
				String userValue = userDn.substring("cn=".length());
				int idx = userValue.indexOf(",");

				if (idx >= 0) {
					userDn = (userValue.substring(0, idx));
				}
			}

			Map<String, String> paramMap = new HashMap<String, String>();
			paramMap.put("userDn", userDn);

			Map<String, String> resultMap = userDao.getUserByCert(paramMap);

			if (resultMap == null || resultMap.size() == 0) {
				// 존재하지 않는 사용자
				setAuditInfo("CERT", "AG", "1", userIp + ", 미존재 사용자 DN, " + spName);
				readyAccessLog("CERT", userIp, TYPE_CERT_LOGIN, spName, userBr, TYPE_ERR_DN_MISMATCH);
				throw new SSOException(MStatus.USER_DN_NOT_EXIST, MStatus.MSG_USER_DN_NOT_EXIST);
			}

			decryptUserInfo(resultMap);
			String userId = (String) resultMap.get("ID");

			if (FLAG_USER_STATUS_LOCKED.equals(resultMap.get("USER_STATUS"))) {
				// 잠긴 사용자
				int interval = config.getInt("user.autounlock.time", 0);
				String accessTime = resultMap.get("ACCESS_TIME") == null ? "" : resultMap.get("ACCESS_TIME");

				if (interval > 0 && !Util.isEmpty(accessTime)) {					
					// ACCESS_TIME 비교
					SimpleDateFormat sdt = new SimpleDateFormat("yyyyMMddHHmmss");
					Date accessDate = sdt.parse(accessTime);
					Calendar cal = Calendar.getInstance();
					cal.setTime(accessDate);
					cal.add(Calendar.MINUTE, interval);
					accessDate = cal.getTime();

					Date curDate = new Date(System.currentTimeMillis());

					int compare = curDate.compareTo(accessDate);
					
					if (compare < 0) {
						setAuditInfo(userId, "AG", "1", userIp + ", 인증 비활성화 상태, " + spName);
						readyAccessLog(userId, userIp, TYPE_CERT_LOGIN, spName, userBr, TYPE_ERR_LOCK);
						throw new SSOException(MStatus.USER_ID_LOCK, MStatus.MSG_USER_ID_LOCK);
					}
				}
				else {
					setAuditInfo(userId, "AG", "1", userIp + ", 인증 비활성화 상태, " + spName);
					readyAccessLog(userId, userIp, TYPE_CERT_LOGIN, spName, userBr, TYPE_ERR_LOCK);
					throw new SSOException(MStatus.USER_ID_LOCK, MStatus.MSG_USER_ID_LOCK);
				}
			}
			else if (FLAG_USER_STATUS_RETIREMENT.equals(resultMap.get("USER_STATUS"))) {
				// 퇴직 사용자
				setAuditInfo(userId, "AG", "1", userIp + ", 퇴직 사용자, " + spName);
				readyAccessLog(userId, userIp, TYPE_CERT_LOGIN, spName, userBr, TYPE_ERR_RETIRE);
				throw new SSOException(MStatus.USER_ID_RETIREMENT, MStatus.MSG_USER_ID_RETIREMENT);
			}
			else {
			}

			if (config.getDupLoginType() == 1) {
				// 선입자우선 중복로그인 방지
				String loginedIp = resultMap.get("NOW_LOGIN_IP") == null ? "" : resultMap.get("NOW_LOGIN_IP");
				String loginedBr = resultMap.get("NOW_LOGIN_BR") == null ? "" : resultMap.get("NOW_LOGIN_BR");
				String accessTime = resultMap.get("ACCESS_TIME") == null ? "" : resultMap.get("ACCESS_TIME");
				int interval = config.getDupAccessTime();
				
				if (!Util.isEmpty(loginedIp) && !userIp.equals(loginedIp)) {
					// IP 다르면 로그인 불가
					if (interval > 0 && !Util.isEmpty(accessTime)) {
						// ACCESS_TIME 비교
						SimpleDateFormat sdt = new SimpleDateFormat("yyyyMMddHHmmss");
						Date accessDate = sdt.parse(accessTime);
						Calendar cal = Calendar.getInstance();
						cal.setTime(accessDate);
						cal.add(Calendar.MINUTE, interval);
						accessDate = cal.getTime();

						Date curDate = new Date(System.currentTimeMillis());

						int compare = curDate.compareTo(accessDate);
						if (compare < 0) {
							setAuditInfo(userId, "AG", "1", userIp + ", " + spName + ", 다른 자리에서 로그인 중인 사용자");
							readyAccessLog(userId, userIp, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_DUP_LOGIN);
							throw new SSOException(MStatus.USER_DUP_LOGIN, "The user account is already logged in");
						}
					}
				}
				else if (!Util.isEmpty(loginedIp) && userIp.equals(loginedIp)) {
					// IP 같고, 브라우저 다르면 로그인 불가
					if (config.getDupBrowser()) {
						if (!Util.isEmpty(loginedBr) && !userBr.equals(loginedBr)) {
							if (interval > 0 && !Util.isEmpty(accessTime)) {
								// ACCESS_TIME 비교
								SimpleDateFormat sdt = new SimpleDateFormat("yyyyMMddHHmmss");
								Date accessDate = sdt.parse(accessTime);
								Calendar cal = Calendar.getInstance();
								cal.setTime(accessDate);
								cal.add(Calendar.MINUTE, interval);
								accessDate = cal.getTime();

								Date curDate = new Date(System.currentTimeMillis());

								int compare = curDate.compareTo(accessDate);
								if (compare < 0) {
									setAuditInfo(userId, "AG", "1", userIp + ", " + userBr + ", " + spName + ", 다른 자리에서 로그인 중인 사용자");
									readyAccessLog(userId, userIp, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_DUP_LOGIN);
									throw new SSOException(MStatus.USER_DUP_LOGIN, "The user account is already logged in");
								}
							}
						}
					}
				}
			}

			setAuditInfo(userId, "AG", "0", userIp + ", " + spName);
			readyAccessLog(userId, userIp, TYPE_CERT_LOGIN, spName, userBr, TYPE_SUCCESS);
			result = createLoginMessage(resultMap, userIp, userBr, loginType);
		}
		catch (SSOException e) {
			log.error("### 인증 실패: {}, {}", userDn, e.getMessage());
			result = createResult(e.getErrorCode(), e.getMessage(), e.getDetailMessage());
		}
		catch (Exception e) {
			log.error("### 인증 오류: {}, {}", userDn, e.getMessage());
			result = createResult(MStatus.ETC_AUTH_FAIL, e.getMessage());
		}

		return result;
	}

	public JSONObject smartLogin(String userId, String userPw, String userDv, String userBr, String spName, String loginType)
	{
		JSONObject result = null;
		SSOConfig config = SSOConfig.getInstance();

		readyAccessLog("", "", "", "", "", "");

		try {
			Map<String, String> paramMap = new HashMap<String, String>();
			paramMap.put("userId", userId);

			Map<String, String> resultMap = userDao.getUserByID(paramMap);

			if (resultMap == null || resultMap.size() == 0) {
				// 존재하지 않는 사용자
				setAuditInfo(userId, "AG", "1", userDv + ", 미존재 사용자 아이디, " + spName);
				readyAccessLog(userId, userDv, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_ID_MISMATCH);
				throw new SSOException(MStatus.USER_ID_NOT_EXIST, MStatus.MSG_USER_ID_NOT_EXIST);
			}

			decryptUserInfo(resultMap);

			if (FLAG_USER_STATUS_LOCKED.equals(resultMap.get("USER_STATUS"))) {
				// 잠긴 사용자
				int interval = config.getInt("user.autounlock.time", 0);
				String accessTime = resultMap.get("ACCESS_TIME") == null ? "" : resultMap.get("ACCESS_TIME");

				if (interval > 0 && !Util.isEmpty(accessTime)) {					
					// ACCESS_TIME 비교
					SimpleDateFormat sdt = new SimpleDateFormat("yyyyMMddHHmmss");
					Date accessDate = sdt.parse(accessTime);
					Calendar cal = Calendar.getInstance();
					cal.setTime(accessDate);
					cal.add(Calendar.MINUTE, interval);
					accessDate = cal.getTime();

					Date curDate = new Date(System.currentTimeMillis());

					int compare = curDate.compareTo(accessDate);
					
					if (compare < 0) {
						setAuditInfo(userId, "AG", "1", userDv + ", 인증 비활성화 상태, " + spName);
						readyAccessLog(userId, userDv, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_LOCK);
						throw new SSOException(MStatus.USER_ID_LOCK, MStatus.MSG_USER_ID_LOCK);
					}
				}
				else {
					setAuditInfo(userId, "AG", "1", userDv + ", 인증 비활성화 상태, " + spName);
					readyAccessLog(userId, userDv, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_LOCK);
					throw new SSOException(MStatus.USER_ID_LOCK, MStatus.MSG_USER_ID_LOCK);
				}
			}
			else if (FLAG_USER_STATUS_RETIREMENT.equals(resultMap.get("USER_STATUS"))) {
				// 퇴직 사용자
				setAuditInfo(userId, "AG", "1", userDv + ", 퇴직 사용자, " + spName);
				readyAccessLog(userId, userDv, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_RETIRE);
				throw new SSOException(MStatus.USER_ID_RETIREMENT, MStatus.MSG_USER_ID_RETIREMENT);
			}
			else {
			}

			// 중복 로그인
			// if

			// 패스워드 검사
			if (!FLAG_FUNC_CERT0005.equals(userPw)) {
				userPw = hashCrypto.getHashWithSalt(userPw, resultMap.get("PW_UPDATE_TIME"));
				log.debug("### hash = " + userPw);

				if (!userPw.equals(resultMap.get("USER_PASSWORD"))) {
					if (FLAG_USER_STATUS_LOCKED.equals(resultMap.get("USER_STATUS"))) {
						// 잠긴 사용자
						setAuditInfo(userId, "AG", "1", userDv + ", 인증 비활성화 상태, " + spName);
						readyAccessLog(userId, userDv, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_LOCK);
						throw new SSOException(MStatus.USER_ID_LOCK, MStatus.MSG_USER_ID_LOCK);
					}
					else {
						int PWMismatchCount = Integer.parseInt((String) resultMap.get("PW_MISMATCH_COUNT"));
						int PWMismatchAllow = Integer.parseInt((String) resultMap.get("PW_MISMATCH_ALLOW"));

						if ((PWMismatchCount + 1) >= PWMismatchAllow) {
							// 패스워드 오류 회수 증가
							userDao.setPWMismatchCount(userId, String.valueOf(PWMismatchAllow), FLAG_USER_STATUS_LOCKED);

							// 사용자 계정 잠김, 메일 발송
							sendMail("MSND0000", Util.getDateFormat("yyyy-MM-dd  HH:mm:ss"), "사용자", userId);

							setAuditInfo(userId, "AG", "1", userDv + ", 패스워드 오류, 인증 비활성화 상태로 변경, " + spName);
							readyAccessLog(userId, userDv, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_LOCK);
							throw new SSOException(MStatus.USER_ID_LOCK, "User Account is now Locking");
						}
						else {
							// 패스워드 오류 회수 증가
							userDao.setPWMismatchCount(userId, String.valueOf(PWMismatchCount + 1), FLAG_USER_STATUS_ACTIVE);

							String countInfo = (PWMismatchCount + 1) + ">" + PWMismatchAllow;

							// 패스워드 오류
							setAuditInfo(userId, "AG", "1", userDv + ", 패스워드 오류, " + spName);
							readyAccessLog(userId, userDv, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_PW_MISMATCH);
							throw new SSOException(MStatus.USER_PW_NOT_MATCH, "Password mismatch. left try count: "
									+ (PWMismatchAllow - PWMismatchCount - 1), countInfo);
						}
					}
				}
				else {
					setAuditInfo(userId, "AG", "0", userDv + ", " + spName);
					readyAccessLog(userId, userDv, TYPE_IDPW_LOGIN, spName, userBr, TYPE_SUCCESS);
					result = createLoginMessage(resultMap, userDv, userBr, loginType);
				}
			}
			else {
				setAuditInfo(userId, "AG", "0", userDv + ", " + spName);
				readyAccessLog(userId, userDv, TYPE_ID_LOGIN, spName, userBr, TYPE_SUCCESS);
				result = createLoginMessage(resultMap, userDv, userBr, "ID_NOPW");
			}
		}
		catch (SSOException e) {
			log.error("### 인증 실패: {}, {}", userId, e.getMessage());
			result = createResult(e.getErrorCode(), e.getMessage(), e.getDetailMessage());
		}
		catch (Exception e) {
			log.error("### 인증 오류: {}, {}", userId, e.getMessage());
			result = createResult(MStatus.ETC_AUTH_FAIL, e.getMessage());
		}

		return result;
	}

	public JSONObject smartLogin2FA(String userId, String userPw, String userDv, String userBr, String spName, String loginType, String authStep, String MFAtype)
	{
		JSONObject result = null;
		SSOConfig config = SSOConfig.getInstance();

		readyAccessLog("", "", "", "", "", "");

		try {
			Map<String, String> paramMap = new HashMap<String, String>();
			paramMap.put("userId", userId);

			Map<String, String> resultMap = userDao.getUserByID(paramMap);

			if (resultMap == null || resultMap.size() == 0) {
				// 존재하지 않는 사용자
				setAuditInfo(userId, "AG", "1", userDv + ", 미존재 사용자 아이디, " + spName);
				readyAccessLog(userId, userDv, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_ID_MISMATCH);
				throw new SSOException(MStatus.USER_ID_NOT_EXIST, MStatus.MSG_USER_ID_NOT_EXIST);
			}

			decryptUserInfo(resultMap);

			if (FLAG_USER_STATUS_LOCKED.equals(resultMap.get("USER_STATUS"))) {
				// 잠긴 사용자
				int interval = config.getInt("user.autounlock.time", 0);
				String accessTime = resultMap.get("ACCESS_TIME") == null ? "" : resultMap.get("ACCESS_TIME");

				if (interval > 0 && !Util.isEmpty(accessTime)) {					
					// ACCESS_TIME 비교
					SimpleDateFormat sdt = new SimpleDateFormat("yyyyMMddHHmmss");
					Date accessDate = sdt.parse(accessTime);
					Calendar cal = Calendar.getInstance();
					cal.setTime(accessDate);
					cal.add(Calendar.MINUTE, interval);
					accessDate = cal.getTime();

					Date curDate = new Date(System.currentTimeMillis());

					int compare = curDate.compareTo(accessDate);
					
					if (compare < 0) {
						setAuditInfo(userId, "AG", "1", userDv + ", 인증 비활성화 상태, " + spName);
						readyAccessLog(userId, userDv, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_LOCK);
						throw new SSOException(MStatus.USER_ID_LOCK, MStatus.MSG_USER_ID_LOCK);
					}
				}
				else {
					setAuditInfo(userId, "AG", "1", userDv + ", 인증 비활성화 상태, " + spName);
					readyAccessLog(userId, userDv, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_LOCK);
					throw new SSOException(MStatus.USER_ID_LOCK, MStatus.MSG_USER_ID_LOCK);
				}
			}
			else if (FLAG_USER_STATUS_RETIREMENT.equals(resultMap.get("USER_STATUS"))) {
				// 퇴직 사용자
				setAuditInfo(userId, "AG", "1", userDv + ", 퇴직 사용자, " + spName);
				readyAccessLog(userId, userDv, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_RETIRE);
				throw new SSOException(MStatus.USER_ID_RETIREMENT, MStatus.MSG_USER_ID_RETIREMENT);
			}
			else {
			}

			// 중복 로그인
			// if

			// 패스워드 검사
			if (!FLAG_FUNC_CERT0005.equals(userPw)) {
				userPw = hashCrypto.getHashWithSalt(userPw, resultMap.get("PW_UPDATE_TIME"));
				//log.debug("### hash = " + userPw);

				if (!userPw.equals(resultMap.get("USER_PASSWORD"))) {
					if (FLAG_USER_STATUS_LOCKED.equals(resultMap.get("USER_STATUS"))) {
						// 잠긴 사용자
						setAuditInfo(userId, "AG", "1", userDv + ", 인증 비활성화 상태, " + spName);
						readyAccessLog(userId, userDv, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_LOCK);
						throw new SSOException(MStatus.USER_ID_LOCK, MStatus.MSG_USER_ID_LOCK);
					}
					else {
						int PWMismatchCount = Integer.parseInt((String) resultMap.get("PW_MISMATCH_COUNT"));
						int PWMismatchAllow = Integer.parseInt((String) resultMap.get("PW_MISMATCH_ALLOW"));

						if ((PWMismatchCount + 1) >= PWMismatchAllow) {
							// 패스워드 오류 회수 증가
							userDao.setPWMismatchCount(userId, String.valueOf(PWMismatchAllow), FLAG_USER_STATUS_LOCKED);

							// 사용자 계정 잠김, 메일 발송
							sendMail("MSND0000", Util.getDateFormat("yyyy-MM-dd  HH:mm:ss"), "사용자", userId);

							setAuditInfo(userId, "AG", "1", userDv + ", 패스워드 오류, 인증 비활성화 상태로 변경, " + spName);
							readyAccessLog(userId, userDv, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_LOCK);
							throw new SSOException(MStatus.USER_ID_LOCK, "User Account is now Locking");
						}
						else {
							// 패스워드 오류 회수 증가
							userDao.setPWMismatchCount(userId, String.valueOf(PWMismatchCount + 1), FLAG_USER_STATUS_ACTIVE);

							String countInfo = (PWMismatchCount + 1) + ">" + PWMismatchAllow;

							// 패스워드 오류
							setAuditInfo(userId, "AG", "1", userDv + ", 패스워드 오류, " + spName);
							readyAccessLog(userId, userDv, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_PW_MISMATCH);
							throw new SSOException(MStatus.USER_PW_NOT_MATCH, "Password mismatch. left try count: "
									+ (PWMismatchAllow - PWMismatchCount - 1), countInfo);
						}
					}
				}
				else {
					if (authStep.equals("1st")) {
						setAuditInfo(userId, "AG", "0", userDv + ", " + spName);
						readyAccessLog(userId, userDv, TYPE_IDPW_LOGIN, spName, userBr, TYPE_SUCCESS);
						result = createResult(MStatus.SUCCESS, "SUCCESS");
					}
					else if (authStep.equals("2nd")) {
						setAuditInfo(userId, "BH", "0", userDv + ", " + spName + ", 인증유형: " + MFAtype);
						readyAccessLog(userId, userDv, TYPE_2FA_LOGIN, spName, userBr, TYPE_SUCCESS);
						result = createLoginMessage(resultMap, userDv, userBr, loginType);
					}
					else {
						log.error("### Unknown authentication step: {}, {}", userId, authStep);
						result = createResult(MStatus.ETC_AUTH_FAIL, "Unknown authentication step");
					}
				}
			}
			else {
				if (authStep.equals("1st")) {
					setAuditInfo(userId, "AG", "0", userDv + ", " + spName);
					readyAccessLog(userId, userDv, TYPE_ID_LOGIN, spName, userBr, TYPE_SUCCESS);
					result = createResult(MStatus.SUCCESS, "SUCCESS");
				}
				else if (authStep.equals("2nd")) {
					setAuditInfo(userId, "BH", "0", userDv + ", " + spName + ", 인증유형: " + MFAtype);
					readyAccessLog(userId, userDv, TYPE_2FA_LOGIN, spName, userBr, TYPE_SUCCESS);
					result = createLoginMessage(resultMap, userDv, userBr, "ID_PW");
				}
				else {
					log.error("### Unknown authentication step: {}, {}", userId, authStep);
					result = createResult(MStatus.ETC_AUTH_FAIL, "Unknown authentication step");
				}
			}
		}
		catch (SSOException e) {
			log.error("### 인증 실패: {}, {}", userId, e.getMessage());
			result = createResult(e.getErrorCode(), e.getMessage(), e.getDetailMessage());
		}
		catch (Exception e) {
			log.error("### 인증 오류: {}, {}", userId, e.getMessage());
			result = createResult(MStatus.ETC_AUTH_FAIL, e.getMessage());
		}

		return result;
	}

	public JSONObject oidcLogin(String userId, String userPw, String userIp, String userBr, String spName, String loginType)
	{
		JSONObject result = null;
		SSOConfig config = SSOConfig.getInstance();

		readyAccessLog("", "", "", "", "", "");

		try {
			Map<String, String> paramMap = new HashMap<String, String>();
			paramMap.put("userId", userId);

			Map<String, String> resultMap = userDao.getUserByID(paramMap);

			if (resultMap == null || resultMap.size() == 0) {
				// 존재하지 않는 사용자
				setAuditInfo(userId, "AG", "1", userIp + ", 미존재 사용자 아이디, " + spName);
				readyAccessLog(userId, userIp, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_ID_MISMATCH);
				throw new SSOException(MStatus.ERR_USER_NOT_EXIST, MStatus.MSG_USER_ID_NOT_EXIST);
			}

			decryptUserInfo(resultMap);

			if (FLAG_USER_STATUS_LOCKED.equals(resultMap.get("USER_STATUS"))) {
				// 잠긴 사용자
				int interval = config.getInt("user.autounlock.time", 0);
				String accessTime = resultMap.get("ACCESS_TIME") == null ? "" : resultMap.get("ACCESS_TIME");

				if (interval > 0 && !Util.isEmpty(accessTime)) {					
					// ACCESS_TIME 비교
					SimpleDateFormat sdt = new SimpleDateFormat("yyyyMMddHHmmss");
					Date accessDate = sdt.parse(accessTime);
					Calendar cal = Calendar.getInstance();
					cal.setTime(accessDate);
					cal.add(Calendar.MINUTE, interval);
					accessDate = cal.getTime();

					Date curDate = new Date(System.currentTimeMillis());

					int compare = curDate.compareTo(accessDate);
					
					if (compare < 0) {
						setAuditInfo(userId, "AG", "1", userIp + ", 인증 비활성화 상태, " + spName);
						readyAccessLog(userId, userIp, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_LOCK);
						throw new SSOException(MStatus.ERR_USER_ID_LOCK, MStatus.MSG_USER_ID_LOCK);
					}
				}
				else {
					setAuditInfo(userId, "AG", "1", userIp + ", 인증 비활성화 상태, " + spName);
					readyAccessLog(userId, userIp, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_LOCK);
					throw new SSOException(MStatus.ERR_USER_ID_LOCK, MStatus.MSG_USER_ID_LOCK);
				}
			}
			else if (FLAG_USER_STATUS_RETIREMENT.equals(resultMap.get("USER_STATUS"))) {
				// 퇴직 사용자
				setAuditInfo(userId, "AG", "1", userIp + ", 퇴직 사용자, " + spName);
				readyAccessLog(userId, userIp, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_RETIRE);
				throw new SSOException(MStatus.ERR_USER_ID_RETIREMENT, MStatus.MSG_USER_ID_RETIREMENT);
			}
			else {
			}

			if (config.getDupLoginType() == 1) {
				// 선입자우선 중복로그인 방지
				String loginedIp = resultMap.get("NOW_LOGIN_IP") == null ? "" : resultMap.get("NOW_LOGIN_IP");
				String loginedBr = resultMap.get("NOW_LOGIN_BR") == null ? "" : resultMap.get("NOW_LOGIN_BR");
				String accessTime = resultMap.get("ACCESS_TIME") == null ? "" : resultMap.get("ACCESS_TIME");
				int interval = config.getDupAccessTime();
				
				if (!Util.isEmpty(loginedIp) && !userIp.equals(loginedIp)) {
					// IP 다르면 로그인 불가
					if (interval > 0 && !Util.isEmpty(accessTime)) {
						// ACCESS_TIME 비교
						SimpleDateFormat sdt = new SimpleDateFormat("yyyyMMddHHmmss");
						Date accessDate = sdt.parse(accessTime);
						Calendar cal = Calendar.getInstance();
						cal.setTime(accessDate);
						cal.add(Calendar.MINUTE, interval);
						accessDate = cal.getTime();

						Date curDate = new Date(System.currentTimeMillis());

						int compare = curDate.compareTo(accessDate);
						if (compare < 0) {
							setAuditInfo(userId, "AG", "1", userIp + ", " + spName + ", 다른 자리에서 로그인 중인 사용자");
							readyAccessLog(userId, userIp, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_DUP_LOGIN);
							throw new SSOException(MStatus.ERR_USER_DUP_LOGIN, "The user account is already logged in");
						}
					}
				}
				else if (!Util.isEmpty(loginedIp) && userIp.equals(loginedIp)) {
					// IP 같고, 브라우저 다르면 로그인 불가
					if (config.getDupBrowser()) {
						if (!Util.isEmpty(loginedBr) && !userBr.equals(loginedBr)) {
							if (interval > 0 && !Util.isEmpty(accessTime)) {
								// ACCESS_TIME 비교
								SimpleDateFormat sdt = new SimpleDateFormat("yyyyMMddHHmmss");
								Date accessDate = sdt.parse(accessTime);
								Calendar cal = Calendar.getInstance();
								cal.setTime(accessDate);
								cal.add(Calendar.MINUTE, interval);
								accessDate = cal.getTime();

								Date curDate = new Date(System.currentTimeMillis());

								int compare = curDate.compareTo(accessDate);
								if (compare < 0) {
									setAuditInfo(userId, "AG", "1", userIp + ", " + userBr + ", " + spName + ", 다른 자리에서 로그인 중인 사용자");
									readyAccessLog(userId, userIp, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_DUP_LOGIN);
									throw new SSOException(MStatus.ERR_USER_DUP_LOGIN, "The user account is already logged in");
								}
							}
						}
					}
				}
			}

			// 패스워드 검사
			if (!FLAG_FUNC_CERT0005.equals(userPw)) {
				userPw = hashCrypto.getHashWithSalt(userPw, resultMap.get("PW_UPDATE_TIME"));
				//log.debug("### hash = " + userPw);

				if (!userPw.equals(resultMap.get("USER_PASSWORD"))) {
					if (FLAG_USER_STATUS_LOCKED.equals(resultMap.get("USER_STATUS"))) {
						// 잠긴 사용자
						setAuditInfo(userId, "AG", "1", userIp + ", 인증 비활성화 상태, " + spName);
						readyAccessLog(userId, userIp, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_LOCK);
						throw new SSOException(MStatus.ERR_USER_ID_LOCK, MStatus.MSG_USER_ID_LOCK);
					}
					else {
						int PWMismatchCount = Integer.parseInt((String) resultMap.get("PW_MISMATCH_COUNT"));
						int PWMismatchAllow = Integer.parseInt((String) resultMap.get("PW_MISMATCH_ALLOW"));

						if ((PWMismatchCount + 1) >= PWMismatchAllow) {
							// 패스워드 오류 회수 증가
							userDao.setPWMismatchCount(userId, String.valueOf(PWMismatchAllow), FLAG_USER_STATUS_LOCKED);

							// 사용자 계정 잠김, 메일 발송
							sendMail("MSND0000", Util.getDateFormat("yyyy-MM-dd  HH:mm:ss"), "사용자", userId);

							setAuditInfo(userId, "AG", "1", userIp + ", 패스워드 오류, 인증 비활성화 상태로 변경, " + spName);
							readyAccessLog(userId, userIp, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_LOCK);
							throw new SSOException(MStatus.ERR_USER_ID_LOCK, "User Account is now Locking");
						}
						else {
							// 패스워드 오류 회수 증가
							userDao.setPWMismatchCount(userId, String.valueOf(PWMismatchCount + 1), FLAG_USER_STATUS_ACTIVE);

							String countInfo = (PWMismatchCount + 1) + ">" + PWMismatchAllow;

							// 패스워드 오류
							setAuditInfo(userId, "AG", "1", userIp + ", 패스워드 오류, " + spName);
							readyAccessLog(userId, userIp, TYPE_IDPW_LOGIN, spName, userBr, TYPE_ERR_PW_MISMATCH);
							throw new SSOException(MStatus.ERR_USER_PW_NOT_MATCH, "Password mismatch. left try count: "
									+ (PWMismatchAllow - PWMismatchCount - 1), countInfo);
						}
					}
				}
				else {
					setAuditInfo(userId, "AG", "0", userIp + ", " + spName);
					readyAccessLog(userId, userIp, TYPE_IDPW_LOGIN, spName, userBr, TYPE_SUCCESS);
					result = createLoginMessage(resultMap, userIp, userBr, loginType);
				}
			}
			else {
				setAuditInfo(userId, "AG", "0", userIp + ", " + spName);
				readyAccessLog(userId, userIp, TYPE_ID_LOGIN, spName, userBr, TYPE_SUCCESS);
				result = createLoginMessage(resultMap, userIp, userBr, "ID_NOPW");
			}
		}
		catch (SSOException e) {
			log.error("### 인증 실패: {}, {}", userId, e.getMessage());
			result = createResult(e.getErrorCode(), e.getMessage(), e.getDetailMessage());
		}
		catch (Exception e) {
			log.error("### 인증 오류: {}, {}", userId, e.getMessage());
			result = createResult(MStatus.ERR_OIDC_LOGIN_FAIL, e.getMessage());
		}

		return result;
	}

	public void decryptUserInfo(Map<String, String> resultMap)
	{
		try {
			CryptoApi crypto = CryptoApiFactory.getCryptoApi();

			if (!"0".equals(resultMap.get("PW_MISMATCH_ALLOW"))) {
				resultMap.put("PW_MISMATCH_ALLOW", new String(crypto.decryptByDEK(resultMap.get("PW_MISMATCH_ALLOW"))));
			}

			if (!"0".equals(resultMap.get("PW_VALIDATE"))) {
				resultMap.put("PW_VALIDATE", new String(crypto.decryptByDEK(resultMap.get("PW_VALIDATE"))));
			}

			if (!"0".equals(resultMap.get("PW_CHANGE_WARN"))) {
				resultMap.put("PW_CHANGE_WARN", new String(crypto.decryptByDEK(resultMap.get("PW_CHANGE_WARN"))));
			}

			if (!"0".equals(resultMap.get("POLLING_TIME"))) {
				resultMap.put("POLLING_TIME", new String(crypto.decryptByDEK(resultMap.get("POLLING_TIME"))));
			}

			if (!"0".equals(resultMap.get("SESSION_TIME"))) {
				resultMap.put("SESSION_TIME", new String(crypto.decryptByDEK(resultMap.get("SESSION_TIME"))));
			}
		}
		catch (Exception e) {
			log.error("### decryptUserInfo() Exception: {}", e.toString());
		}
	}

	private JSONObject createLoginMessage(Map<String, String> resultMap, String userIp, String userBr, String loginType) throws SSOException, SQLException
	{
		JSONObject result = new JSONObject();
		SSOConfig config = SSOConfig.getInstance();

		String userId = resultMap.get("ID");

		resultMap.put("NOW_LOGIN_IP", userIp);
		resultMap.put("LOGIN_TYPE", loginType);

		// Verify Token
		if (Util.isEmpty(resultMap.get("NAME"))) {
			setAuditInfo(userId, "AG", "1", userIp + ", 인증토큰 중요 정보 없음(사용자 이름)");
			throw new SSOException(MStatus.CREATE_TOKEN_FAIL, "Create Token failed");
		}
		else if (Util.isEmpty(resultMap.get("TIMESTAM_"))) {
			setAuditInfo(userId, "AG", "1", userIp + ", 인증토큰 중요 정보 없음(서버시간)");
			throw new SSOException(MStatus.CREATE_TOKEN_FAIL, "Create Token failed");
		}
		else if (Util.isEmpty(resultMap.get("NOT_AFTER"))) {
			setAuditInfo(userId, "AG", "1", userIp + ", 인증토큰 중요 정보 없음(서버시간)");
			throw new SSOException(MStatus.CREATE_TOKEN_FAIL, "Create Token failed");
		}

		// 후입자우선 중복로그인 방지 옵션: 선입자 정보 토큰 추가
		if (config.getDupPreLogin()) {
			String preLogin = DupClient.getPreLogin(userId, userIp, userBr);
			resultMap.put("PRE_LOGIN", preLogin);
		}

		// Create Token
		resultMap = replaceMapKey(resultMap);
		String strToken = createTokenString("[USER]", resultMap);

		StringBuilder userToken = new StringBuilder();
		userToken.append(strToken).append("[APPLDEFAULT]");

		try { Util.zeroize(strToken); } catch (Exception e) {}

		// Init User Access Info
		userDao.setUserAccessInfo(userId, userIp, userBr);
		writeAccessLog();

		// 후입자우선 중복로그인 방지
		if (config.getDupLoginType() == 2) {
			if (userBr.equals("MB")) {
				DupClient.putLogin("mobile", userId, userIp, userBr);
			}
			else {
				DupClient.putLogin("dream", userId, userIp, userBr);
			}
		}

		result.put("code", String.valueOf(MStatus.SUCCESS));
		result.put("message", "SUCCESS");
		result.put("data", userToken);
		return result;
	}

	private static Map<String, String> replaceMapKey(Map<String, String> resultMap)
	{
		ArrayList<String> sourceList = SSOConfig.getInstance().getListProperty("token.attribute");

		if (sourceList == null || sourceList.size() == 0 || "*".equals(sourceList.get(0))) {
			return resultMap;
		}

		Map<String, String> replaceMap = new HashMap<String, String>();

		for (int i = 0, limit = sourceList.size(); i < limit; i++) {
			String key = (String) sourceList.get(i);

			if (resultMap.containsKey(key)) {
				if (key.equals("TIMESTAM_")) {
					replaceMap.put("TIMESTAMP", resultMap.get(key));
				}
				else {
					replaceMap.put(key, resultMap.get(key));
				}
			}
			else {
				replaceMap.put(key, "");
			}
		}

		return replaceMap;
	}

	protected String createTokenString(String header, Map resultMap)
	{
		StringBuilder resultString = new StringBuilder(header).append("\n");

		if (resultMap != null) {
			for (Iterator iterator = resultMap.keySet().iterator(); iterator.hasNext();) {
				String key = (String) iterator.next();
				String value = (String) resultMap.get(key);
				resultString.append(key).append("=").append(value == null ? "" : value).append("\n");
			}

			resultString.append("\n");
		}

		return resultString.toString();
	}

	public void clearLoginIP(String userId, String userIp, String userBr)
	{
		try {
			userDao.clearLoginIP(userId, userIp, userBr);
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
	}

	public void clearIpInfo(String userId, String userIp, String userBr)
	{
		try {
			userDao.clearIpInfo(userId, userIp, userBr);
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
	}

	public void setConnectLog(String userId, String userIp, String userBr, String spName)
	{
		readyAccessLog(userId, userIp, TYPE_CONNECT_LOGIN, spName, userBr, TYPE_SUCCESS);
		writeAccessLog();
	}

	public void setLogoutLog(String userId, String userIp, String userBr, String loginType, String spName)
	{
		if (loginType.equals("ID_PW")) {
			readyAccessLog(userId, userIp, TYPE_IDPW_LOGOUT, spName, userBr, TYPE_SUCCESS);
		}
		else if (loginType.equals("ID_NOPW")) {
			readyAccessLog(userId, userIp, TYPE_ID_LOGOUT, spName, userBr, TYPE_SUCCESS);
		}
		else if (loginType.equals("CERT")) {
			readyAccessLog(userId, userIp, TYPE_CERT_LOGOUT, spName, userBr, TYPE_SUCCESS);
		}
		else {
			readyAccessLog(userId, userIp, TYPE_LOGOUT, spName, userBr, TYPE_SUCCESS);
		}

		writeAccessLog();
	}

	public int setUserPwd(String id, String curPwd, String newPwd)
	{
		try {
			Map<String, String> paramMap = new HashMap<String, String>();
			paramMap.put("userId", id);

			Map<String, String> resultMap = userDao.getUserByID(paramMap);

			if (resultMap == null || resultMap.size() == 0) {
				throw new SSOException(MStatus.USER_ID_NOT_EXIST, MStatus.MSG_USER_ID_NOT_EXIST);
			}

			String frPwd = hashCrypto.getHashWithSalt(curPwd, resultMap.get("PW_UPDATE_TIME"));

			String curTime = Util.getDateFormat("yyyyMMddHHmmss");
			String toPwd = hashCrypto.getHashWithSalt(newPwd, curTime);

			paramMap.put("curPwd", frPwd);
			paramMap.put("newPwd", toPwd);
			paramMap.put("update", curTime);

			int cnt = userDao.setUserPwd(paramMap);

			if (cnt > 0) {
				setAuditInfo(id, "AI", "0", "");
			}
			else {
				setAuditInfo(id, "AI", "1", "비밀번호 불일치");
			}

			return cnt;
		}
		catch (SQLException e) {
			setAuditInfo(id, "AI", "1", "Exception : " + e.getMessage());
			log.error("### setUserPwd() SQLException: {}, {}", e.getErrorCode(), e.toString());
		}
		catch (SSOException e) {
			setAuditInfo(id, "AI", "1", "Exception : " + e.getMessage());
			log.error("### setUserPwd() SSOException: {}, {}", e.getErrorCode(), e.toString());
		}

		return 0;
	}

	public JSONObject checkFirstLogin(String id)
	{
		JSONObject result = new JSONObject();

		try {
			Map<String, String> paramMap = new HashMap<String, String>();
			paramMap.put("userId", id);

			Map<String, String> resultMap = userDao.getUserByID(paramMap);

			if (resultMap == null || resultMap.size() == 0) {
				log.error("### checkFirst(), {}, Non-Existent Users", id);

				result.put("code", String.valueOf(MStatus.API_NON_EXISTENT_USERS));
				result.put("message", "Non-Existent Users");
				result.put("data", "");
				return result;
			}

			String first = Util.isEmpty(resultMap.get("PW_UPDATE_TIME")) ? "0" : "1";

			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", first);
		}
		catch (SQLException e) {
			setAuditInfo(id, "AI", "1", "SQLException: " + e.getErrorCode());
			log.error("### setUserPw() SQLException: {}, {}", e.getErrorCode(), e.toString());

			result.put("code", String.valueOf(MStatus.API_EXCEPTION));
			result.put("message", "Exception: " + e.getErrorCode() + ", " + e.getMessage());
			result.put("data", "");
		}

		return result;
	}

	public JSONObject setInitPw(String id, String newPwd)
	{
		JSONObject result = new JSONObject();

		try {
			String curTime = Util.getDateFormat("yyyyMMddHHmmss");
			String toPwd = hashCrypto.getHashWithSalt(newPwd, curTime);

			Map<String, String> paramMap = new HashMap<String, String>();
			paramMap.put("userId", id);
			paramMap.put("newPwd", toPwd);
			paramMap.put("update", curTime);

			int cnt = userDao.setUserPwd(paramMap);

			if (cnt > 0) {
				setAuditInfo(id, "AI", "0", "");

				result.put("code", String.valueOf(MStatus.SUCCESS));
				result.put("message", "SUCCESS");
				result.put("data", "");
			}
			else {
				setAuditInfo(id, "AI", "1", "Update Count: 0");
				log.error("### setInitPw(), {}, Update Count: 0", id);

				result.put("code", String.valueOf(MStatus.API_UPDATE_ZERO));
				result.put("message", "Update Count: 0");
				result.put("data", "");
			}
		}
		catch (SQLException e) {
			setAuditInfo(id, "AI", "1", "SQLException: " + e.getErrorCode());
			log.error("### setInitPw() SQLException: {}, {}", e.getErrorCode(), e.toString());

			result.put("code", String.valueOf(MStatus.API_EXCEPTION));
			result.put("message", "Exception: " + e.getErrorCode() + ", " + e.getMessage());
			result.put("data", "");
		}

		return result;
	}

	public JSONObject setChangePw(String id, String curPwd, String newPwd)
	{
		JSONObject result = new JSONObject();

		try {
			Map<String, String> paramMap = new HashMap<String, String>();
			paramMap.put("userId", id);

			Map<String, String> resultMap = userDao.getUserByID(paramMap);

			if (resultMap == null || resultMap.size() == 0) {
				setAuditInfo(id, "AI", "1", "Non-Existent Users");
				log.error("### setChangePw(), {}, Non-Existent Users", id);

				result.put("code", String.valueOf(MStatus.API_NON_EXISTENT_USERS));
				result.put("message", "Non-Existent Users");
				result.put("data", "");
				return result;
			}

			String frPwd = hashCrypto.getHashWithSalt(curPwd, resultMap.get("PW_UPDATE_TIME"));

			if (!frPwd.equals(resultMap.get("USER_PASSWORD"))) {
				setAuditInfo(id, "AI", "1", "Password mismatch");
				log.error("### setChangePw(), {}, Password mismatch", id);

				result.put("code", String.valueOf(MStatus.API_PASSWORD_MISMATCH));
				result.put("message", "Password mismatch");
				result.put("data", "");
				return result;
			}

			String curTime = Util.getDateFormat("yyyyMMddHHmmss");
			String toPwd = hashCrypto.getHashWithSalt(newPwd, curTime);

			paramMap.put("curPwd", frPwd);
			paramMap.put("newPwd", toPwd);
			paramMap.put("update", curTime);

			int cnt = userDao.setUserPwd(paramMap);

			if (cnt > 0) {
				setAuditInfo(id, "AI", "0", "");

				result.put("code", String.valueOf(MStatus.SUCCESS));
				result.put("message", "SUCCESS");
				result.put("data", "");
			}
			else {
				setAuditInfo(id, "AI", "1", "Update Count: 0");
				log.error("### setChangePw(), {}, Update Count: 0", id);

				result.put("code", String.valueOf(MStatus.API_UPDATE_ZERO));
				result.put("message", "Update Count: 0");
				result.put("data", "");
			}
		}
		catch (SQLException e) {
			setAuditInfo(id, "AI", "1", "SQLException: " + e.getErrorCode());
			log.error("### setUserPw() SQLException: {}, {}", e.getErrorCode(), e.toString());

			result.put("code", String.valueOf(MStatus.API_EXCEPTION));
			result.put("message", "Exception: " + e.getErrorCode() + ", " + e.getMessage());
			result.put("data", "");
		}

		return result;
	}

	public JSONObject setUnlockUser(String id)
	{
		JSONObject result = new JSONObject();

		try {
			Map<String, String> paramMap = new HashMap<String, String>();
			paramMap.put("userId", id);

			int cnt = userDao.setUserUnlock(paramMap);

			if (cnt > 0) {
				setAuditInfo(id, "AQ", "0", "사용자:"+id);

				result.put("code", String.valueOf(MStatus.SUCCESS));
				result.put("message", "SUCCESS");
				result.put("data", "");
			}
			else {
				setAuditInfo(id, "AQ", "1", "Update Count: 0");
				log.error("### setUnlockUser(), {}, Update Count: 0", id);

				result.put("code", String.valueOf(MStatus.API_UPDATE_ZERO));
				result.put("message", "Update Count: 0");
				result.put("data", "");
			}
		}
		catch (SQLException e) {
			setAuditInfo(id, "AQ", "1", "SQLException: " + e.getErrorCode());
			log.error("### setUnlockUser() SQLException: {}, {}", e.getErrorCode(), e.toString());

			result.put("code", String.valueOf(MStatus.API_EXCEPTION));
			result.put("message", "Exception: " + e.getErrorCode() + ", " + e.getMessage());
			result.put("data", "");
		}

		return result;
	}

	public JSONObject checkPw(String id, String pw)
	{
		JSONObject result = new JSONObject();

		try {
			Map<String, String> paramMap = new HashMap<String, String>();
			paramMap.put("userId", id);

			Map<String, String> resultMap = userDao.getUserByID(paramMap);

			if (resultMap == null || resultMap.size() == 0) {
				log.error("### checkPw(), {}, Non-Existent Users", id);

				result.put("code", String.valueOf(MStatus.API_NON_EXISTENT_USERS));
				result.put("message", "Non-Existent Users");
				result.put("data", "");
				return result;
			}

			String frPwd = hashCrypto.getHashWithSalt(pw, resultMap.get("PW_UPDATE_TIME"));

			if (!frPwd.equals(resultMap.get("USER_PASSWORD"))) {
				log.error("### checkPw(), {}, Password mismatch", id);

				result.put("code", String.valueOf(MStatus.API_PASSWORD_MISMATCH));
				result.put("message", "Password mismatch");
				result.put("data", "");
				return result;
			}

			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", "");
		}
		catch (SQLException e) {
			log.error("### checkPw() SQLException: {}, {}", e.getErrorCode(), e.toString());

			result.put("code", String.valueOf(MStatus.API_EXCEPTION));
			result.put("message", "Exception: " + e.getErrorCode() + ", " + e.getMessage());
			result.put("data", "");
		}

		return result;
	}

	public String getCSLoginTime(String id)
	{
		try {
			Map<String, String> resultMap = userDao.getCSLoginTime(id);

			if (resultMap == null || resultMap.size() == 0) {
				return "";
			}

			return resultMap.get("CS_LOGIN_TIME") == null ? "" : resultMap.get("CS_LOGIN_TIME");
		}
		catch (SQLException e) {
			e.printStackTrace();
		}

		return "";
	}

	public void setCSLoginTime(String id)
	{
		try {
			userDao.setCSLoginTime(id);
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
	}

	public void clearCSLoginTime(String id, String ip)
	{
		try {
			userDao.clearCSLoginTime(id, ip);
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
	}

	public Map<String, String> getOidcUserInfo(String id, String[] scopeList) throws Exception
	{
		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("id", id);
		paramMap.put("scopeList", scopeList);

		return userDao.getOidcUserInfo(paramMap);
	}
}