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
	String type = request.getParameter("type") == null ? "" : request.getParameter("type");
	String email = request.getParameter("email") == null ? "" : request.getParameter("email");
	String menucode = request.getParameter("menucode") == null ? "" : request.getParameter("menucode");

	String result = checkAdmin(adminid, admintype, adminmenu, "0401");
	if (!result.equals("")) {
		response.getWriter().write(result);
		return;
	}

	if (Util.isEmpty(uid) || Util.isEmpty(name) || Util.isEmpty(type)) {
		result = "Error : 처리 조건을 입력하세요.";
	}
	else {
		AdminController adminApi = new AdminController();

		if (checkAdminCSRFToken(request)) {
			result = adminApi.setAdminInfo(adminid, newflag, uid, name, pwd, type, email, menucode);
		}
		else {
			result = "Error : 유효하지 않은 페이지입니다.\n\n해당 페이지를 다시 호출하세요.";
		}
	}

	response.getWriter().write(result);
%>