package com.dreamsecurity.sso.server.api;

import javax.servlet.http.HttpServletRequest;

import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.server.session.RootAuthSession;

public interface UserApi
{
	public int connectTest();

	public JSONObject login(HttpServletRequest request);
	public JSONObject loginCert(HttpServletRequest request);
	public JSONObject smartLogin(HttpServletRequest request);
	public JSONObject smartLogin2FA(HttpServletRequest request);
	public JSONObject oidcLogin(HttpServletRequest request, RootAuthSession rootAuthSession);
	public JSONObject login(HttpServletRequest request, RootAuthSession rootAuthSession);

	public void clearLoginIP(String userId, String userIp, String userBr);
	public void clearIpInfo(String userId, String userIp, String userBr);

	public void setConnectLog(String userId, String userIp, String userBr, String spName);
	public void setLogoutLog(String userId, String userIp, String userBr, String loginType, String spName);

	public String setUserPwd(String id, String curPwd, String newPwd);

	public String setUserInfo(String encData);

	public String getCSLoginTime(String id);
	public void setCSLoginTime(String id);
	public void clearCSLoginTime(String id, String ip);
	
	public JSONObject getOidcUserInfo(String id, String[] scopeList);
}