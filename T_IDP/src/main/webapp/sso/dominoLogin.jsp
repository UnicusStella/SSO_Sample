<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%
	if (session.getAttribute("SSO_ID") != null && !session.getAttribute("SSO_ID").equals("")) {
		response.sendRedirect("/sso/inc/sessionView.jsp");
	}
%>
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Domino 로그인 샘플 페이지</title>
<style type="text/css">
.blue_btn {text-align:center; margin:0;}
.blue_btn button {width:100px; height:66px; padding:1px; border-radius:5px; border:0; background:#175deb;
	-webkit-appearance:none; box-shadow:1px 1px 0 #D9D9D9; -webkit-box-shadow:1px 1px 0 #D9D9D9; cursor:pointer;}
.blue_btn button span {font-size:16px; font-weight:bold; color:#FEFEFE; text-shadow:1px 1px 0 rgba(0,0,0,.2);
	-webkit-text-shadow:1px 1px 0 rgba(0,0,0,.2)}
.login-input {height:26px; width:175px; font-size:14px; padding-left:7px;}
</style>
<script type="text/javascript">
	document.onkeypress = getKey;

	function getKey(keyStroke)
	{
		if (window.event.keyCode == 13)
			loginStart();
	}

	function loginStart()
	{
		var frm = document.getElementById("loginForm");

		if (frm.loginId.value == "" || frm.loginPw.value == "") {
			alert("아이디 또는 비밀번호를 입력해 주세요.");
			return;
		}

		frm.action = "/sso/dmRequestS.jsp";
		frm.submit();
	}
</script>
</head>
<body bgcolor="#E6E6E6">
	<div id="mainPage">
		<form name="loginForm" id="loginForm" method="post">
		<input type="hidden" id="returnUrl" name="returnUrl" value="/sso/inc/sessionView.jsp"/>
		<input type="hidden" id="reqType" name="reqType" value="auth"/>

		<table width="100%" bgcolor="#E6E6E6" border="0" cellpadding="0" cellspacing="0">
			<tr height="30">
				<td></td>
			</tr>
			<tr>
				<td>
					<table width="530" border="1" bordercolor="#E1E1E1" style="border-collapse:collapse" cellpadding="0" cellspacing="0" align="center">
						<tr>
							<td>
								<div style="width:530px; height:270px; background-image:url('/sso/images/login_main_img.jpg'); background-repeat:no-repeat; background-size:auto;">
								</div>
							</td>
						</tr>
						<tr height="100" bgcolor="#FFFFFF">
							<td>
								<table width="100%" border="0" cellpadding="0" cellspacing="0">
									<tr height="40">
										<td width="14%"></td>
										<td width="15%" align="right"><b>아이디&nbsp;&nbsp;</b></td>
										<td width="36%">
											<input class="login-input" type="text" name="loginId" id="loginId" tabindex=1 maxlength="20">
										</td>
										<td width="22%" rowspan="2" align="center">
											<p class="blue_btn">
												<button type="button" name="btIdPw" id="btIdPw" tabindex=3 onclick="loginStart(); return false;">
													<span>로그인</span>
												</button>
											</p>
										</td>
										<td width="13%"></td>
									</tr>
									<tr height="40">
										<td></td>
										<td align="right"><b>비밀번호&nbsp;&nbsp;</b></td>
										<td>
											<input class="login-input" type="password" name="loginPw" id="loginPw" tabindex=2 maxlength="20">
										</td>
										<td></td>
									</tr>
								</table>
							</td>
						</tr>
					</table>
				</td>
			</tr>
			<tr height="35">
				<td align="center">Copyright 2010 DreamSecurity. All rights reserved.</td>
			</tr>
		</table>
		</form>
	</div>
</body>
</html>