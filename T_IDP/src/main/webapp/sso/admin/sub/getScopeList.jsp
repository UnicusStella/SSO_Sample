<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.admin.AdminController"%>
<%@ include file="./subCommon.jsp"%>
<%
	String result = "";

	AdminController adminApi = new AdminController();
	result = adminApi.getScopeList();

	response.getWriter().write(result);
%>