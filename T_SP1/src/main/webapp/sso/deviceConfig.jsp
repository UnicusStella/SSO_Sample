<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.dreamsecurity.sso.lib.jsn.JSONObject"%>
<%@ page import="com.dreamsecurity.sso.agent.config.*"%>
<%@ page import="com.dreamsecurity.sso.agent.exception.SSOException"%>
<%@ page import="com.dreamsecurity.sso.agent.provider.ServiceProvider"%>
<%@ include file="./commonM.jsp"%>
<%
	JSONObject result = null;

	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);
	SSOInit.initialize();

	try {
		result = ServiceProvider.getInstance().getSmartConfig();

		if (result == null) {
			throw new SSOException("Device Initialization data null");
		}
	}
	catch (SSOException e) {
		result = new JSONObject();
		result.put("code", String.valueOf(6901));
		result.put("message", "SP: " + e.getMessage());
		result.put("data", "");
	}

	out.println(result.toJSONString());
%>