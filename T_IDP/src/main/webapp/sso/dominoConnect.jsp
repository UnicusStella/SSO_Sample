<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title></title>
<script type="text/javascript">
function goNext()
{
	var frm = document.getElementById("ssoForm");
    frm.action = "/sso/dmRequestS.jsp";
    frm.submit();
}
</script>
</head>
<body onload="goNext(); return false;">
<form id="ssoForm" name="ssoForm" method="post">
	<input type="hidden" id="returnUrl" name="returnUrl" value="/sso/inc/sessionView.jsp"/>
	<input type="hidden" id="reqType" name="reqType" value="connect"/>
</form>
</body>
</html>