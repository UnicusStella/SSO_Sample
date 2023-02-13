<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.dreamsecurity.sso.lib.jsn.JSONObject"%>
<%@ page import="com.dreamsecurity.sso.agent.common.MStatus"%>
<%@ page import="com.dreamsecurity.sso.agent.config.*"%>
<%@ page import="com.dreamsecurity.sso.agent.exception.SSOException"%>
<%@ page import="com.dreamsecurity.sso.agent.provider.ServiceProvider"%>
<%@ page import="com.dreamsecurity.sso.agent.util.Util"%>
<%@ include file="./commonM.jsp"%>
<%
	out.clear();
	//out = pageContext.pushBody();

	String encData = request.getParameter("ED") == null ? "" : request.getParameter("ED");
	String relaystate = request.getParameter("RelayState") == null ? "" : request.getParameter("RelayState");

	if (Util.isEmpty(encData)) {
		Util.sendErrorURL(response, ERROR_URL, "6908", "SP: ConnectEx parameter is empty", DEFAULT_BASE_URL);
		return;
	}

	if (Util.isEmpty(relaystate)) {
		relaystate = RELAY_STATE;
	}

	request.setAttribute("relaystate", relaystate);
	request.setAttribute("requesturl", IDP_REQUEST_URL);
	request.setAttribute("responseurl", SP_RESPONSE_URL);

	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);
	SSOInit.initialize();

	JSONObject result = null;

	try {
		result = ServiceProvider.getInstance().smartRequestConnectEx(request, encData);

		if (result == null) {
			Util.sendErrorURL(response, ERROR_URL, "6909", "SP: ConnectEx result null", DEFAULT_BASE_URL);
			return;
		}

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			Util.sendErrorURL(response, ERROR_URL, (String) result.get("code"), (String) result.get("message"), DEFAULT_BASE_URL);
			return;
		}

		if (((String) result.get("message")).equals("T")) {
			result.put("message", "SUCCESS");

			out.println(result.toJSONString());
			return;
		}

		if (result.get("data") == null) {
			Util.sendErrorURL(response, ERROR_URL, "6910", "SP: ConnectEx result data null", DEFAULT_BASE_URL);
			return;
		}
	}
	catch (Exception e) {
		Util.sendErrorURL(response, ERROR_URL, "6911", "SP ConnectEx Exception: " + e.getMessage(), DEFAULT_BASE_URL);
	}

 	boolean sendResult = Util.sendAuthnRequest(response, IDP_REQUEST_URL, (String) result.get("data"), "connectExM");

	if (!sendResult) {
		session.removeAttribute("LGCHLG");
		Util.sendErrorURL(response, ERROR_URL, "6912", "SP: ConnectEx request send failure", DEFAULT_BASE_URL);
	}
%>