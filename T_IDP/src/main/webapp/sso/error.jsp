<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ include file="./common.jsp"%>
<%
	String code = request.getParameter("ecode") == null ? "" : request.getParameter("ecode");
	String message = request.getParameter("emessage") == null ? "" : request.getParameter("emessage");
	String msg = " " + code + ", " + message;
%>
<html>
<head>
<title>Request Error Page</title>
</head>
<script type="text/javascript">
	//alert(" < %=XSSCheck(msg)% >");
 	alert(" 사용자 인증 실패");
 	location.href = "<%=XSSCheck(DEFAULT_BASE_URL)%>";
</script>
</html>