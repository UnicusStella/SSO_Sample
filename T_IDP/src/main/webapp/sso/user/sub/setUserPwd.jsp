<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.UserApi"%>
<%@ page import="com.dreamsecurity.sso.server.api.UserApiFactory"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ include file="./subCommon.jsp"%>
<%
	String userId = request.getParameter("uid") == null ? "" : request.getParameter("uid");
	String curPwd = request.getParameter("curpwd") == null ? "" : request.getParameter("curpwd");
	String newPwd = request.getParameter("newpwd") == null ? "" : request.getParameter("newpwd");
	String result = "";

	if (Util.isEmpty(userId) || Util.isEmpty(curPwd) || Util.isEmpty(newPwd)) {
		result = "Error : 처리 조건을 입력하세요.";
	}
	else {
		UserApi userApi = UserApiFactory.getUserApi();

		if (checkAdminCSRFToken(request)) {
			result = userApi.setUserPwd(userId, curPwd, newPwd);
		}
		else {
			result = "Error : 유효하지 않은 페이지입니다.\n\n해당 페이지를 다시 호출하세요.";
		}
	}

	response.getWriter().write(result);
%>