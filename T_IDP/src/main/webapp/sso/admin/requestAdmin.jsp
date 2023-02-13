<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.lib.jsn.JSONObject"%>
<%@ page import="com.dreamsecurity.sso.server.common.MStatus"%>
<%@ page import="com.dreamsecurity.sso.server.api.admin.AdminController"%>
<%@ page import="com.dreamsecurity.sso.server.config.SSOConfig"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ include file="./adminCommon.jsp"%>
<%
	out.clear();
	out = pageContext.pushBody(); 

	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);
	request.setAttribute("loginBr", getBrowserType(request));

	AdminController adminApi = new AdminController();
	JSONObject result = adminApi.adminLogin(request);

	if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
		Util.sendErrorURL(response, LOGIN_ERROR_PAGE, (String) result.get("code"), (String) result.get("message"));
		return;
	}
	else {
		Util.sendURL(response, ADMIN_MAIN_PAGE);
		return;
	}
%>