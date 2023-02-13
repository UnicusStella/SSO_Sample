<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%><%@
page import="com.dreamsecurity.sso.server.api.*"%><%
	String encData = request.getParameter("ED") == null ? "" : request.getParameter("ED");

	UserApi userApi = UserApiFactory.getUserApi();
	String result = userApi.setUserInfo(encData);

	response.getWriter().write(result);
%>