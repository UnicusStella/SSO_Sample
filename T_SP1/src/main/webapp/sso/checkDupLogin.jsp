<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.dreamsecurity.sso.agent.config.*"%>
<%@ page import="com.dreamsecurity.sso.agent.dup.DupClient"%>
<%@ page import="com.dreamsecurity.sso.agent.util.Util"%>
<%@ include file="./common.jsp"%>
<%
	out.clear();

	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);
	SSOInit.initialize();

	String uid = session.getAttribute(SESSION_SSO_ID) == null ? "" : (String) session.getAttribute(SESSION_SSO_ID);
	String uip = Util.getClientIP(request);
	String ubr = Util.getBrowserType(request);

	if (!Util.isEmpty(uid)) {
		String result = DupClient.checkLogin(uid, uip, ubr);

		if (result != null && result.length() >= 3) {
			if (result.substring(0, 3).equals("DUP")) {
				String dupinfo = result.substring(3);
				Util.sendDupLogoutURL(response, LOGOUT_URL, dupinfo);
				return;
			}

			if (result.substring(0, 3).equals("OUT")) {
				Util.sendLogoutURL(response, LOGOUT_URL);
				return;
			}
		}
	}

	boolean idpCheck = true;
	if (idpCheck) {
		Util.sendURL(response, IDP_CHECK_URL);
	}
%>