<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.dreamsecurity.sso.lib.dss.s2.core.AuthnRequest"%>
<%@ page import="com.dreamsecurity.sso.lib.dss.s2.core.Response"%>
<%@ page import="com.dreamsecurity.sso.lib.jsn.JSONObject"%>
<%@ page import="com.dreamsecurity.sso.server.common.MStatus"%>
<%@ page import="com.dreamsecurity.sso.server.config.SSOConfig"%>
<%@ page import="com.dreamsecurity.sso.server.exception.SSOException"%>
<%@ page import="com.dreamsecurity.sso.server.provider.IdentificationProvider"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ page import="com.dreamsecurity.sso.server.util.SendUtil"%>
<%@ include file="./common.jsp"%>
<%
	out.clear();
	out = pageContext.pushBody();

	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);
	request.setAttribute("loginBr", getBrowserType(request));

	String baseURL = Util.getBaseURL(request);
	String errorURL = baseURL + DEFAULT_SSO_PATH + ERROR_PAGE;

	IdentificationProvider idp = null;
	AuthnRequest authnRequest = null;
	JSONObject result = null;

	try {
		idp = IdentificationProvider.getInstance();
		result = idp.authnIDPLoginS(request, request.getParameter(PARAM_LOGIN_ID), request.getParameter(PARAM_LOGIN_PW));

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			Util.sendErrorURL(response, errorURL, (String) result.get("code"), (String) result.get("message"));
			return;
		}
	}
	catch (SSOException e) {
		Util.sendErrorURL(response, errorURL, String.valueOf(e.getErrorCode()), e.getMessage());
		return;
	}

	result = null;
	result = idp.generateResponseS(request);

	if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
		Util.sendErrorURL(response, errorURL, (String) result.get("code"), (String) result.get("message"));
		return;
	}

 	boolean sendResult = SendUtil.sendResponse(response, request, (String) result.get("data"));

 	if (!sendResult) {
		Util.sendErrorURL(response, errorURL, String.valueOf(MStatus.AUTH_REQ_SEND), "IDP: Send Response Failure");
 	}
%>