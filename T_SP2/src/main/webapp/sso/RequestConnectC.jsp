<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.dreamsecurity.sso.lib.jsn.JSONObject"%>
<%@ page import="com.dreamsecurity.sso.agent.common.MStatus"%>
<%@ page import="com.dreamsecurity.sso.agent.config.*"%>
<%@ page import="com.dreamsecurity.sso.agent.exception.SSOException"%>
<%@ page import="com.dreamsecurity.sso.agent.provider.ServiceProvider"%>
<%@ page import="com.dreamsecurity.sso.agent.util.Util"%>
<%@ include file="./common.jsp"%>
<%
	String tcheck = request.getParameter("T") == null ? "" : request.getParameter("T");

	if (tcheck.equals("1")) {
		String timeStamp = Util.getDecimalTime();
		out.println(timeStamp);
		return;
	}

	out.clear();
	out = pageContext.pushBody();

	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);
	SSOInit.initialize();

	String baseURL = Util.getBaseURL(request);
	String errorURL = baseURL + DEFAULT_SSO_PATH + ERROR_PAGE;

	ServiceProvider sp = null;
	JSONObject result = null;

	try {
		sp = ServiceProvider.getInstance();
		//result = sp.getConnectCSData(request, SESSION_SSO_ID);
		result = sp.getConnectCSData(request, SESSION_SSO_TOKEN);

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			Util.sendErrorURL(response, errorURL, (String) result.get("code"), (String) result.get("message"));
			return;
		}

		String ED = (String) result.get("data");
		//System.out.println(ED);

		//*************************************************
		// 연계 C/S 프로그램 실행 코딩 구현, 실행 시 ED 값 전달 필수
		// Custom URI Scheme 방식으로 C/S 프로그램 실행 시 샘플
		// Custom URI Scheme: "cstest", param: ED
		Util.sendCustomUriScheme(response, "cstest", ED);
	}
	catch (SSOException e) {
		Util.sendErrorURL(response, errorURL, String.valueOf(e.getErrorCode()), e.getMessage());
		return;
	}
%>