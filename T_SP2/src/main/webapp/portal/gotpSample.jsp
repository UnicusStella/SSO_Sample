<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%
	if (session.getAttribute("SSO_ID") == null || session.getAttribute("SSO_ID").equals("")) {
		response.sendRedirect("/portal/loginSample.jsp");
	}
%>
<!DOCTYPE html>
<html lang="ko">
<head>
<title>Magic SSO - Login Sample</title>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" type="text/css" href="css/dream_sso.css">
<script>
document.onkeypress = getKey;

document.addEventListener("DOMContentLoaded", function(){
	document.getElementById("otpCode").focus();
});

function getKey(keyStroke)
{
	if (window.event.keyCode == 13)
		verifyOTP();
}

function verifyOTP()
{
	var frm = document.getElementById("loginForm");

	if (frm.otpCode.value == "" || frm.otpCode.value.length !== 6) {
		alert(" 6자리 OTP 코드를 입력해 주세요.");
		return;
	}

	frm.action = "/sso/gotpAuthSample.jsp";
	frm.submit();
}
</script>
</head>
<body>
<form name="loginForm" id="loginForm" method="post">
<input type="hidden" name="RelayState" value=""/>
<div class="wrap">
    <div class="con_wrap">
        <div class="contents_box">
            <div class="login_area">
                <div class="login_box">
                    <div class="login_tit">
                        <img src="images/login_logo.png" alt="Magic SSO"><br/><span>Google OTP 인증</span>
                    </div>
                    <div class="input_wrap">
                        <input type="text" class="input_box width_80p mb_10" name="otpCode" id="otpCode" placeholder="OTP Code" tabindex=1 maxlength="50" autocomplete="off"/>
                        <button type="button" class="blue_btn width_80p" onclick="verifyOTP(); return false;"><span>인 증</span></button>
                    </div>
                </div>
            </div>
            <div class="contact_noti">
                <span>Copyright ⓒ Dreamsecurity Co.,Ltd. All rights reserved.</span>
            </div>
        </div>
    </div>
</div>
</form>
</body>
</html>