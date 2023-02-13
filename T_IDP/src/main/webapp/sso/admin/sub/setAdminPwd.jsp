<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.admin.AdminController"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ include file="./subCommon.jsp"%>
<%@ include file="./checkAdmin.jsp"%>
<%
	String userId = request.getParameter("uid") == null ? "" : request.getParameter("uid");
	String curPwd = request.getParameter("curpwd") == null ? "" : request.getParameter("curpwd");
	String newPwd = request.getParameter("newpwd") == null ? "" : request.getParameter("newpwd");
	String result = "";

	if (adminid.equals("")) {
		result = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":-9,\"resultdata\":\"\"}]}";
		response.getWriter().write(result);
		return;
	}

	if (Util.isEmpty(userId) || Util.isEmpty(curPwd) || Util.isEmpty(newPwd)) {
		result = "Error : 처리 조건을 입력하세요.";
	}
	else {
		AdminController adminApi = new AdminController();

		if (checkAdminCSRFToken(request)) {
			result = adminApi.setAdminPwd(request, userId, curPwd, newPwd, adminsalt, adminfirst);
		}
		else {
			result = "Error : 유효하지 않은 페이지입니다.\n\n해당 페이지를 다시 호출하세요.";
		}
	}

	response.getWriter().write(result);
%>