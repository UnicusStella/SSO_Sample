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
<meta http-equiv="content-type" content="text/html; charset=UTF-8" />
<script type="text/javascript" src="/MagicLine4Web/ML4Web/js/ext/jquery-1.10.2.js"></script>
<script type="text/javascript" src="/MagicLine4Web/ML4Web/js/ext/jquery-ui.min.js"></script>
<script type="text/javascript" src="/MagicLine4Web/ML4Web/js/ext/jquery.blockUI.js"></script>
<script type="text/javascript" src="/MagicLine4Web/ML4Web/js/ext/json2.js"></script>
<!-- ML4WEB JS -->
<script type="text/javascript" src="/MagicLine4Web/ML4Web/js/ext/ML_Config.js"></script>
<link rel="stylesheet" type="text/css" href="css/dream_sso.css">
<script type="text/javascript">
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

function mlCallBack(code, message)
{
	if (code == 0)
	{
		// 정상메시지
		var data = encodeURIComponent(message.encMsg);

		document.loginForm.signedData.value = data;

		//alert(data);
		//alert(message.vidRandom);
	
		if (message.vidRandom != null){
			document.loginForm.vidRandom.value = encodeURIComponent(message.vidRandom);
		}

		document.loginForm.action = "/sso/RequestAuthCert.jsp";
		document.loginForm.submit();
	}
	else {
		alert("결과값 수신에 실패하였습니다.");
		return;
	}
}
</script>
</head>
<body>
<form name="loginForm" id="loginForm" method="post">
<input type="hidden" id="RelayState" name="RelayState" value=""/>
<input type="hidden" id="signData" name="signData"  value="Login"/>
<input type="hidden" id="signedData" name="signedData"/>
<input type="hidden" id="vidRandom" name="vidRandom"/>
<input type="hidden" id="vidType" name="vidType" value="client"/>

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
                        <button type="button" class="blue_btn width_40p" onclick="loginStart(); return false;"><span>로그인</span></button>
                        <button type="button" class="blue_btn width_40p" name="btCert" id="btCert" onclick="javascript:magicline.uiapi.MakeSignData(document.loginForm, null, mlCallBack);"><span>인증서 로그인</span></button>
                    </div>
                </div>
            </div>
            <div class="contact_noti">
                <span>Copyright ⓒ Dreamsecurity Co.,Ltd. All rights reserved.</span>
            </div>
        </div>
    </div>
</div>
<div id="dscertContainer">
    <iframe id="dscert" name="dscert" src="" width="100%" height="100%" frameborder="0" allowTransparency="true" style="position:fixed;z-index:100010;top:0px;left:0px;width:100%;height:100%;"></iframe>
</div>
</form>
</body>
</html>