<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%
	if (session.getAttribute("SSO_ID") != null && !session.getAttribute("SSO_ID").equals("")) {
		response.sendRedirect("/portal/main.jsp");  // edit
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
	document.getElementById("loginId").focus();
});

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

	frm.action = "/sso/RequestAuth.jsp";
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
                        <img src="images/login_logo.png" alt="Magic SSO"><br/><span>로그인</span>
                    </div>
                    <div class="input_wrap">
                        <input type="text" class="input_box width_80p mb_10" name="loginId" id="loginId" placeholder="ID" tabindex=1 maxlength="50" autocomplete="off"/>
                        <input type="password" class="input_box width_80p mb_20" name="loginPw" id="loginPw" placeholder="PW" tabindex=2 maxlength="50"/>
                        <button type="button" class="blue_btn width_80p" onclick="loginStart(); return false;"><span>로그인</span></button>
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