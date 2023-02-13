<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.admin.AdminController"%>
<%@ page import="com.dreamsecurity.sso.server.crypto.SSOCryptoApi"%>
<%@ include file="adminCommon.jsp"%>
<%
	if (session.getAttribute("SSO_ADMIN_ID") != null) {
		response.sendRedirect(DEFAULT_SSO_PATH + "/admin/main.jsp");
	}

	AdminController adminApi = new AdminController();
	String challenge = adminApi.createLoginCSRFToken(request);
%>
<!DOCTYPE html>
<html lang="ko">
<head>
<title>Magic SSO Admin</title>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" type="text/css" href="/sso/admin/css/sso-adminlogin.css">
<link rel="shortcut icon" href="/sso/admin/images/ds_tab.ico">
<script type="text/javascript" src="/sso/admin/js/seed.js"></script>
<script type="text/javascript" src="/sso/admin/js/sha256.js"></script>
<script type="text/javascript">
document.onkeypress = getKey;

document.addEventListener("DOMContentLoaded", function(){
	document.getElementById("uid").focus();
});

function getKey(keyStroke)
{
	if (window.event.keyCode == 13)
		loginStart();
}

function loginStart()
{
	var frm = document.getElementById("loginForm");

	if (frm.uid.value == "" || frm.upw.value == "") {
		alert("아이디 또는 비밀번호를 입력해 주세요.");
		return;
	}

	var hval = CryptoJS.SHA256("<%=XSSCheck(challenge)%>").toString();
	var key = CryptoJS.enc.Hex.parse(hval.substr(0, 32));
	var iv = CryptoJS.enc.Hex.parse(hval.substr(32, 32));

	var encId = CryptoJS.SEED.encrypt(frm.uid.value, key, { iv: iv }, { mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
	var encPw = CryptoJS.SEED.encrypt(frm.upw.value, key, { iv: iv }, { mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });

	frm.loginId.value = encId.ciphertext.toString();
	frm.loginPw.value = encPw.ciphertext.toString();

	frm.uid.value = "";
	frm.upw.value = "";

	frm.action = "/sso/admin/requestAdmin.jsp";
	frm.submit();
}
</script>
</head>
<body>
<form name="loginForm" id="loginForm" method="post">
<input type="hidden" id="loginId" name="loginId" value=""/>
<input type="hidden" id="loginPw" name="loginPw" value=""/>
<input type="hidden" id="loginCh" name="loginCh" value="<%=XSSCheck(challenge)%>"/>
<input type="hidden" id="RelayState" name="RelayState" value=""/>
<div class="wrap">
    <div class="con_wrap">
        <div class="contents_box">
            <div class="login_area">
                <div class="login_box">
                    <div class="login_tit">
                        <img src="/sso/admin/css/images/login_logo.png" alt="Magic SSO"><br/><span>관리자 로그인</span>
                    </div>
                    <div class="input_wrap">
                        <input type="text" class="input_box width_80p mb_10" name="uid" id="uid" placeholder="ID" tabindex=1 maxlength="50" autocomplete="off"/>
                        <input type="password" class="input_box width_80p mb_20" name="upw" id="upw" placeholder="PW" tabindex=2 maxlength="50"/>
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