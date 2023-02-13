<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.net.URLDecoder"%>
<%@ page import="java.net.InetAddress"%>
<%@ page import="java.net.*"%>
<%@ page import="java.util.Map"%>
<%@ page import="java.util.HashMap"%>
<%@ page import="com.dreamsecurity.sso.lib.jsn.JSONObject"%>
<%@ page import="com.dreamsecurity.sso.lib.jtm.DateTime"%>
<%@ page import="com.dreamsecurity.sso.lib.jtm.DateTimeZone"%>
<%@ page import="com.dreamsecurity.sso.agent.common.MStatus"%>
<%@ page import="com.dreamsecurity.sso.agent.exception.SSOException"%>
<%@ page import="com.dreamsecurity.sso.agent.token.SSOToken"%>
<%@ page import="com.dreamsecurity.sso.agent.provider.ServiceProvider"%>
<%@ page import="com.dreamsecurity.sso.agent.util.Util"%>
<%@ page import="com.dreamsecurity.sso.agent.config.SSOConfig"%>
<%@ include file="./common.jsp"%>
<%
	out.clear();
	out = pageContext.pushBody();

	String baseURL = Util.getBaseURL(request);
	System.out.println(baseURL);
	String errorURL = baseURL + DEFAULT_SSO_PATH + ERROR_PAGE;
	String message = ERROR_ROLE_MESSAGE;

	// sessionAttrMap : key=samlresponse attribute name, value=session attribute name
	Map<String, String> sessionAttrMap = new HashMap<String, String>();
	sessionAttrMap.put(SSOToken.PROP_NAME_ID, "SSO_ID");
	sessionAttrMap.put("POLLING_TIME", "POLLING_TIME");
	sessionAttrMap.put("SESSION_TIME", "SSO_INACTIVE");

	ServiceProvider sp = null;
	JSONObject result = null;

	try {
		sp = ServiceProvider.getInstance();
		result = sp.readResponse(request, response, sessionAttrMap);

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			Util.sendErrorURL(response, errorURL, (String) result.get("code"), (String) result.get("message"));
			return;
		}
	}
	catch (SSOException e) {
		Util.sendErrorURL(response, errorURL, String.valueOf(e.getErrorCode()), e.getMessage());
		return;
	}

	String relayState = URLDecoder.decode(request.getParameter(PARAM_RELAYSTATE), "UTF-8");

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