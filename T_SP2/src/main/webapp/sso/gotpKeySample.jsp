<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.dreamsecurity.sso.agent.config.*"%>
<%@ page import="com.dreamsecurity.sso.agent.otp.GoogleOTP"%>
<%@ include file="./common.jsp"%>
<%
	out.clear();
	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);

	out.println(GoogleOTP.createSecretKey(16));
%>