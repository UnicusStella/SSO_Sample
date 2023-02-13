<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ include file="adminCommon.jsp"%>
<html>
<head>
<title>Request Error Page</title>
</head>
<script type="text/javascript">
	alert(" 관리자 인증 실패");
	parent.location.href = "<%=XSSCheck(LOGIN_PAGE)%>";
</script>
</html>