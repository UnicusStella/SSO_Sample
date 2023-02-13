<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.dreamsecurity.sso.agent.config.*"%>
<%@ page import="com.dreamsecurity.sso.agent.util.Util"%>
<%@ page import="com.dreamsecurity.sso.agent.otp.GoogleOTP"%>
<%@ include file="./common.jsp"%>
<%
	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);
	SSOInit.initialize();

	String otp = request.getParameter("otpCode");
	String msg = "";

	if (Util.isEmpty(otp)) {
		msg = " OTP Code is Empty";
	}
	else {
		boolean result = GoogleOTP.verify(request, otp);

		if (result) {
			msg = " OTP 인증 성공";
		}
		else {
			msg = " OTP 인증 실패";
		}
	}
%>
<html>
<head>
<title>OTP 인증</title>
</head>
<script type="text/javascript">
 	alert("<%=msg%>");
 	location.href = "/portal/gotpSample.jsp";
</script>
</html>