<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.net.*"%>
<%@ page import="com.dreamsecurity.sso.lib.jsn.JSONObject"%>
<%@ page import="com.dreamsecurity.sso.server.common.MStatus"%>
<%@ page import="com.dreamsecurity.sso.server.config.SSOConfig"%>
<%@ page import="com.dreamsecurity.sso.server.exception.SSOException"%>
<%@ page import="com.dreamsecurity.sso.server.provider.IdentificationProvider"%>
<%@ include file="./common.jsp"%>
<%
	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);
	request.setAttribute("loginBr", getBrowserType(request));

	JSONObject result = null;

	try {
		result = IdentificationProvider.getInstance().authnProxyConnect(request);

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			response.setStatus(401);
			return;
		}

		if (result.get("data") == null) {
			response.setStatus(401);
			return;
		}
	}
	catch (SSOException e) {
		response.setStatus(401);
		return;
	}

	response.setHeader("DSToken", URLEncoder.encode((String) result.get("data"), "UTF-8"));
	response.setStatus(200);
%>