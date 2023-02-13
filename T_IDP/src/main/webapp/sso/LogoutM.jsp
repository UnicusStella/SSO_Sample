<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"
%><%@ page import="com.dreamsecurity.sso.lib.jsn.JSONObject"
%><%@ page import="com.dreamsecurity.sso.server.config.SSOConfig"
%><%@ page import="com.dreamsecurity.sso.server.exception.SSOException"
%><%@ page import="com.dreamsecurity.sso.server.provider.IdentificationProvider"
%><%@ include file="./common.jsp"
%><%
	JSONObject result = null;

	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);

	try {
		result = IdentificationProvider.getInstance().smartLogout(request);

		if (result == null) {
			throw new SSOException("IDP: smartLogout() result null");
		}
	}
	catch (SSOException e) {
		result = new JSONObject();
		result.put("code", String.valueOf(7902));
		result.put("message", "IDP Exception: " + e.getMessage());
		result.put("data", "");
	}

	out.println(result.toJSONString());
%>