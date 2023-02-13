<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.admin.AdminController"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ include file="./subCommon.jsp"%>
<%@ include file="./checkAdmin.jsp"%>
<%
	String newflag = request.getParameter("newflag") == null ? "" : request.getParameter("newflag");
	String uid = request.getParameter("uid") == null ? "" : request.getParameter("uid");
	String name = request.getParameter("name") == null ? "" : request.getParameter("name");
	String pwd = request.getParameter("pwd") == null ? "" : request.getParameter("pwd");

	String result = checkAdmin(adminid, admintype, adminmenu, "0301");
	if (!result.equals("")) {
		response.getWriter().write(result);
		return;
	}

	if (Util.isEmpty(uid) || Util.isEmpty(name)) {
		result = "Error : 처리 조건을 입력하세요.";
	}
	else {
		AdminController adminApi = new AdminController();

		if (checkAdminCSRFToken(request)) {
			result = adminApi.setUserInfo(adminid, newflag, uid, name, pwd);
		}
		else {
			result = "Error : 유효하지 않은 페이지입니다.\n\n해당 페이지를 다시 호출하세요.";
		}
	}

	response.getWriter().write(result);
%>