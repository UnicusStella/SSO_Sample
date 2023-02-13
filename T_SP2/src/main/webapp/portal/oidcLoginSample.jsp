<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%
	if (session.getAttribute("SSO_ID") != null && !session.getAttribute("SSO_ID").equals("")) {
		response.sendRedirect("/sso/inc/oidcSessionView.jsp");  // edit
	}
%>
<!DOCTYPE html>
<html lang="ko">
<head>
<title>Magic SSO - OIDC Login Sample</title>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" type="text/css" href="css/dream_sso.css">
<script>
document.onkeypress = getKey;

function getKey(keyStroke)
{
	if (window.event.keyCode == 13)
		oidcStart();
}

function oidcStart()
{
	var frm = document.getElementById("loginForm");

	frm.action = "/oidc/auth";
	frm.submit();
}
</script>
</head>
<body>
<form name="loginForm" id="loginForm" method="post">
<input type="hidden" id="RelayState" name="RelayState" value=""/>
<div class="wrap">
    <div class="con_wrap">
        <div class="contents_box">
            <div class="login_area">
                <div class="login_box">
                    <div class="login_tit">
                        <img src="images/login_logo.png" alt="Magic SSO"><br/><span>로그인 / 연계</span>
                    </div>
                    <div class="input_wrap">
                        <button type="button" class="blue_btn width_80p mt_50" onclick="oidcStart(); return false;"><span>OpenID Connect</span></button>
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