<%@ page language="java" contentType="text/html; charset=utf-8"  pageEncoding="utf-8"%>
<%@ page import="java.net.HttpURLConnection"%>
<%@ page import="java.net.URL"%>
<%@ include file="./subCommon.jsp"%>
<%@ include file="./checkAdmin.jsp"%>
<%
	String checkUrl = request.getParameter("url") == null ? "" : request.getParameter("url");

	String result = checkAdmin(adminid, admintype, adminmenu, "0103");
	if (!result.equals("")) {
		response.getWriter().write(result);
		return;
	}

	if (checkUrl.equals("")) {
		result = "Error : 처리 조건을 입력하세요.";
	}
	else {
		URL url;
		try {
			url = new URL(checkUrl);
			HttpURLConnection httpURLConn = (HttpURLConnection) url.openConnection();
			httpURLConn.connect();

			if (httpURLConn.getResponseCode() == 200) {
				result = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
			}
			else {
				result = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":-2,\"resultdata\":\"Response Error.\"}]}";
			}
		}
		catch (Exception e) {
			result = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":-1,\"resultdata\":\"Exception Error.\"}]}";
		}
	}

	response.getWriter().write(result);
%>