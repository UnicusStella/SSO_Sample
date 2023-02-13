<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%><%@
page import="com.dreamsecurity.sso.agent.token.SSOToken"%><%!
	public String XSSCheck(String value)
	{
		if (value != null && value.trim().length() > 0) {
			value = value.trim();
			value = value.replaceAll("<", "&lt;");
			value = value.replaceAll(">", "&gt;");
			value = value.replaceAll("&", "&amp;");
			value = value.replaceAll("\'", "&apos;");
		}

		return value;
	}
%><%
	String type = request.getParameter("tp") == null ? "" : (String) request.getParameter("tp");
	String id = request.getParameter("id") == null ? "" : (String) request.getParameter("id");
	String token = session.getAttribute("_TOKEN") == null ? "" : (String) session.getAttribute("_TOKEN");
	String result = "";

	if (token.equals("")) {
		if (type.equals("0")) {
			result = "false";
		}
		else {
			result = "";
		}
	}
	else {
		SSOToken ssoToken = null;

		try {
			ssoToken = new SSOToken(token);
		}
		catch (Exception e) {
			ssoToken = null;
		}

		if (ssoToken == null) {
			if (type.equals("0")) {
				result = "false";
			}
			else {
				result = "";
			}
		}
		else {
			if (type.equals("0")) {
				result = "true";
			}
			else if (type.equals("1")) {
				result = ssoToken.getProperty("ID");
			}
			else if (type.equals("2")) {
				result = token;
			}
			else if (type.equals("3")) {
				result = ssoToken.getProperty(id);
			}
			else {
				result = "";
			}
		}
	}
%><%=XSSCheck(result)%>