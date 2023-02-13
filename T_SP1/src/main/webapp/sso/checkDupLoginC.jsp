<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.dreamsecurity.sso.agent.config.*"%>
<%@ page import="com.dreamsecurity.sso.agent.dup.DupClient"%>
<%@ page import="com.dreamsecurity.sso.lib.jsn.JSONObject"%>
<%@ include file="./common.jsp"%>
<%
	JSONObject result = null;

	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);
	SSOInit.initialize();

	String encData = request.getParameter("ED") == null ? "" : request.getParameter("ED");

	if (!Util.isEmpty(encData)) {
		result = DupClient.checkLoginC(encData);

		if (result == null) {
			result = new JSONObject();
			result.put("code", String.valueOf(6803));
			result.put("message", "SP checkLoginC: Result Null");
			result.put("data", "");
		}
	}
	else {
		result = new JSONObject();
		result.put("code", String.valueOf(6804));
		result.put("message", "SP checkLoginC: Parameter Empty");
		result.put("data", "");
	}

	out.println(result.toJSONString());
%>