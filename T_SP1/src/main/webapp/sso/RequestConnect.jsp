<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.net.URLEncoder"%>
<%@ page import="java.util.Iterator"%>
<%@ page import="java.util.Map"%>
<%@ page import="com.dreamsecurity.sso.lib.dss.s2.core.AuthnRequest"%>
<%@ page import="com.dreamsecurity.sso.lib.jsn.JSONObject"%>
<%@ page import="com.dreamsecurity.sso.agent.common.MStatus"%>
<%@ page import="com.dreamsecurity.sso.agent.config.*"%>
<%@ page import="com.dreamsecurity.sso.agent.exception.SSOException"%>
<%@ page import="com.dreamsecurity.sso.agent.provider.ServiceProvider"%>
<%@ page import="com.dreamsecurity.sso.agent.util.Util"%>
<%@ page import="com.dreamsecurity.sso.agent.util.SAMLUtil"%>
<%@ include file="./common.jsp"%>
<%
	out.clear();
	out = pageContext.pushBody();

	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);
	SSOInit.initialize();

	String baseURL = Util.getBaseURL(request);
	String errorURL = baseURL + DEFAULT_SSO_PATH + ERROR_PAGE;

	ServiceProvider sp = null;
	JSONObject result = null;

	// multi-IdP
	String idp = request.getParameter("idp") == null ? "" : (String) request.getParameter("idp");

	try {
		sp = ServiceProvider.getInstance();
		result = sp.generateAuthnRequest(request, idp);

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			Util.sendErrorURL(response, errorURL, (String) result.get("code"), (String) result.get("message"));
			return;
		}

		if (result.get("data") == null) {
			Util.sendErrorURL(response, errorURL, String.valueOf(MStatus.FAIL), "Generate AuthnRequest Failure.");
			return;
		}
	}
	catch (SSOException e) {
		Util.sendErrorURL(response, errorURL, String.valueOf(e.getErrorCode()), e.getMessage());
		return;
	}

	// create RelayState start
	String relayState = request.getParameter(PARAM_RELAYSTATE);
	if (Util.isEmpty(relayState)) {
		relayState = DEFAULT_RELAYSTATE;
	}

	relayState = Util.getURL(request, relayState);

	StringBuffer addParam = new StringBuffer();
	Map<?,?> parameterMap = request.getParameterMap();
	Iterator<?> iterator = parameterMap.keySet().iterator();
	while (iterator.hasNext()) {
		String name = (String) iterator.next();
		if (name.equals(PARAM_RELAYSTATE) || name.equals(PARAM_LOGIN_ID)
				|| name.equals(PARAM_LOGIN_PW) || name.equals(PARAM_LOGIN_CH)) {
			continue;
		}

		if (addParam.length() > 0) {
			addParam.append("&");
		}

		addParam.append(name).append("=").append(request.getParameter(name));
	}

	if (!Util.isEmpty(addParam.toString())) {
		int index = relayState.indexOf("?");
		if (index == -1) {
			relayState = relayState + "?" + addParam.toString();
		}
		else {
			relayState = relayState + "&" + addParam.toString();
		}
	}

	relayState = URLEncoder.encode(relayState, "UTF-8");
	// create RelayState end

 	boolean sendResult = SAMLUtil.sendAuthnRequest(response, (AuthnRequest) result.get("data"), "connect", relayState);
 	if (!sendResult) {
		session.removeAttribute("LGCHLG");
		Util.sendErrorURL(response, errorURL, String.valueOf(MStatus.AUTH_REQ_SEND), "Send AuthnRequest Failure.");
 	}
%>