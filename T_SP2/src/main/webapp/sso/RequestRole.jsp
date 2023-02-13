<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.dreamsecurity.sso.lib.jsn.JSONObject"%>
<%@ page import="com.dreamsecurity.sso.agent.common.MStatus"%>
<%@ page import="com.dreamsecurity.sso.agent.exception.SSOException"%>
<%@ page import="com.dreamsecurity.sso.agent.provider.ServiceProvider"%>
<%@ page import="com.dreamsecurity.sso.agent.util.Util"%>
<%@ page import="com.dreamsecurity.sso.agent.config.SSOConfig"%>
<%@ include file="./common.jsp"%>
<%
	out.clear();
	out = pageContext.pushBody();

	String baseURL = Util.getBaseURL(request);
	String errorURL = baseURL + DEFAULT_SSO_PATH + ERROR_PAGE;
	String message = ERROR_ROLE_MESSAGE;

	ServiceProvider sp = null;
	JSONObject result = null;

	String relayState = "";
	if (Util.isEmpty(relayState)) {
		relayState = baseURL + DEFAULT_RELAYSTATE;
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

	String appl = SSOConfig.getInstance().getString("server.applcode", "");

	try {
		if (!Util.isEmpty(appl)) {
			String redirectUrl = HOME_RETURN_ROLE_URL;

			sp = ServiceProvider.getInstance();
			result = sp.generateRoleData(request, appl, redirectUrl);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				Util.sendErrorURL(response, relayState, message);
				return;
			}

			String ED = (String) result.get("data");
			String target = GET_ROLE_URL;

			Util.sendGetRoleURL(response, target, ED, relayState);
		}
		else {
			Util.sendURL(response, relayState);
		}
	}
	catch (SSOException e) {
		Util.sendErrorURL(response, relayState, message);
		return;
	}
%>