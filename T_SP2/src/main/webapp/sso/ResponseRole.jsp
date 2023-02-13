<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.net.URLDecoder"%>
<%@ page import="com.dreamsecurity.sso.lib.jsn.JSONObject"%>
<%@ page import="com.dreamsecurity.sso.agent.common.MStatus"%>
<%@ page import="com.dreamsecurity.sso.agent.exception.SSOException"%>
<%@ page import="com.dreamsecurity.sso.agent.provider.ServiceProvider"%>
<%@ page import="com.dreamsecurity.sso.agent.util.Util"%>
<%@ include file="./common.jsp"%>
<%
	out.clear();
	out = pageContext.pushBody();

	String baseURL = Util.getBaseURL(request);
	String errorURL = baseURL + DEFAULT_SSO_PATH + ERROR_PAGE;
	String relayState = URLDecoder.decode(request.getParameter(PARAM_RELAYSTATE), "UTF-8");
	String message = ERROR_ROLE_MESSAGE;

	ServiceProvider sp = null;
	JSONObject result = null;

	try {
		result = null;
		sp = ServiceProvider.getInstance();

		result = sp.receiveRoleData(request);

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			Util.sendErrorURL(response, relayState, message);
			return;
		}
	}
	catch (SSOException e) {
		Util.sendErrorURL(response, relayState, message);
		return;
	}

	if (Util.isEmpty(relayState)) {
		relayState = DEFAULT_RELAYSTATE;
	}
	else {
		String[] CheckRelayState = relayState.split("\\?");
		boolean allow = false;
		for (int i = 0; i < allowURL.length; i++) {
			if (CheckRelayState[0].equals(allowURL[i])) {
				allow = true;
				break;
			}
		}
		if (!allow) {
			Util.sendURL(response, LOGOUT_URL);
			return;
		}
	}
	Util.sendURL(response, relayState);
%>