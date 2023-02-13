<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.util.OIDCUtil"%>
<%@ include file="./subCommon.jsp"%>
<%
	String result = "";
	String uuid = OIDCUtil.generateUUID();
	result = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\""+uuid+"\"}]}";
	response.getWriter().write(result);
%>