<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.dreamsecurity.sso.lib.jsn.JSONObject"%>
<%@ page import="com.dreamsecurity.sso.agent.config.*"%>
<%@ page import="com.dreamsecurity.sso.agent.exception.SSOException"%>
<%@ page import="com.dreamsecurity.sso.agent.provider.ServiceProvider"%>
<%@ page import="com.dreamsecurity.sso.agent.util.Util"%>
<%@ include file="./commonM.jsp"%>
<%
	JSONObject result = null;

	String encData = request.getParameter("ED") == null ? "" : request.getParameter("ED");

	if (Util.isEmpty(encData)) {
		result = new JSONObject();
		result.put("code", String.valueOf(6905));
		result.put("message", "SP: Connect parameter is Empty");
		result.put("data", "");

		out.println(result.toJSONString());
		return;
	}

	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);
	SSOInit.initialize();

	try {
		result = ServiceProvider.getInstance().smartConnect(IDP_REQUEST_M_URL, encData);

		if (result == null) {
			throw new SSOException("Connect result null");
		}
	}
	catch (SSOException e) {
		result = new JSONObject();
		result.put("code", String.valueOf(6904));
		result.put("message", "SP: " + e.getMessage());
		result.put("data", "");
	}

	out.println(result.toJSONString());
%>