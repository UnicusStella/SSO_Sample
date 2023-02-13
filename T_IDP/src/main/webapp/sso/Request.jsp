<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.dreamsecurity.sso.lib.jsn.JSONObject"%>
<%@ page import="com.dreamsecurity.sso.lib.dss.s2.core.AuthnRequest"%>
<%@ page import="com.dreamsecurity.sso.lib.dss.s2.core.Response"%>
<%@ page import="com.dreamsecurity.sso.server.common.MStatus"%>
<%@ page import="com.dreamsecurity.sso.server.config.SSOConfig"%>
<%@ page import="com.dreamsecurity.sso.server.exception.SSOException"%>
<%@ page import="com.dreamsecurity.sso.server.provider.IdentificationProvider"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ page import="com.dreamsecurity.sso.server.util.SAMLUtil"%>
<%@ include file="./common.jsp"%>
<%
	out.clear();
	out = pageContext.pushBody();

	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);
	request.setAttribute("loginBr", getBrowserType(request));

	String relayState = request.getParameter(TEMPLETE_PARAM_RELAYSTATE);
	String baseURL = Util.getBaseURL(request);
	String errorURL = baseURL + DEFAULT_SSO_PATH + ERROR_PAGE;

	IdentificationProvider idp = null;
	AuthnRequest authnRequest = null;
	JSONObject result = null;

	try {
		idp = IdentificationProvider.getInstance();
		result = idp.receiveAuthnRequest(request);

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			Util.sendErrorURL(response, errorURL, (String) result.get("code"), (String) result.get("message"));
			return;
		}

		if (result.get("data") == null) {
			Util.sendErrorURL(response, errorURL, String.valueOf(MStatus.FAIL), "Receive AuthnRequest Failure");
			return;
		}

		authnRequest = (AuthnRequest) result.get("data");
	}
	catch (SSOException e) {
		Util.sendErrorURL(response, errorURL, String.valueOf(e.getErrorCode()), e.getMessage());
		return;
	}

	boolean bAuthn = idp.checkAuthentication(request);

	if (bAuthn) { // login
		if (idp.checkIDPLogin(request)) {
		 	Util.sendIDPLoginURL(response, baseURL + DEFAULT_SSO_PATH + SERVER_LOGIN_PAGE, relayState);
			return;
		}

		result = null;
		result = idp.authnLogin(request);

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			Util.sendErrorURL(response, errorURL, (String) result.get("code"), (String) result.get("message"));
			return;
		}
	}
	else { // connect
		result = null;
		result = idp.authnConnect(request);

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			Util.sendErrorURL(response, errorURL, (String) result.get("code"), (String) result.get("message"));
			return;
		}
	}

	result = null;
	result = idp.generateResponse(request);

	if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
		Util.sendErrorURL(response, errorURL, (String) result.get("code"), (String) result.get("message"));
		return;
	}

 	boolean sendResult = SAMLUtil.sendResponse(response, (Response) result.get("data"), authnRequest, relayState);

 	if (!sendResult) {
		Util.sendErrorURL(response, errorURL, String.valueOf(MStatus.AUTH_REQ_SEND), "Send Response Failure");
 	}
%>