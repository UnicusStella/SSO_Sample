<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.dreamsecurity.sso.server.config.SSOConfig"%>
<%
	SSOConfig.getInstance().reload();

	//String value = SSOConfig.getInstance().getString("aaa.bbb", "AAAAA");
	//int value = SSOConfig.getInstance().getInt("aaa.bbb", 10);
	boolean value = SSOConfig.getInstance().getBoolean("server.login", false);
%>
<%=value%>