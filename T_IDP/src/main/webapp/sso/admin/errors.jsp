<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ include file="adminCommon.jsp"%>
<html>
<head>
<title>Session Error Page</title>
</head>
<script type="text/javascript">
	alert(" 로그인 후 사용하세요.");
	parent.location.href = "<%=XSSCheck(LOGIN_PAGE)%>";
</script>
</html>