<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ page session="true"%>
<%@ page import="com.dreamsecurity.sso.server.api.admin.AdminController"%>
<%@ include file="adminCommon.jsp"%>
<%@ include file="sub/checkAdmin.jsp"%>
<%
	AdminController adminApi = new AdminController();
	String challenge = adminApi.createAdminCSRFToken(request);
%>
<script type="text/javascript">
	if ("<%=XSSCheck(adminid)%>" == "") { top.location.href = "<%=XSSCheck(LOGIN_PAGE)%>"; }
	if ("<%=XSSCheck(admintype)%>" != "S") { top.location.href = "<%=XSSCheck(LOGOUT_PAGE)%>"; }
</script>

<!DOCTYPE html>
<html lang="ko">
<head>
	<meta charset="utf-8"/>
	<meta http-equiv="Content-Style-Type" content="text/css"/>
	<meta http-equiv="X-UA-Compatible" content="IE=edge"/>

	<!--jgGrid, jsTree Tags-->
	<link href="css/jquery-ui.css" type="text/css" rel="stylesheet"/>
	<link href="css/jquery-ui-1.8.21.custom.css" type="text/css" rel="stylesheet"/>
	<script src="js/jquery-3.4.1.min.js" type="text/javascript"></script>
	<script src="js/jquery-ui-1.12.1.min.js" type="text/javascript"></script>
	<script src="js/!script.js" type="text/javascript"></script>
	<link href="css/!style.css" type="text/css" rel="stylesheet"/>
	<script src="js/i18n/grid.locale-kr.js" type="text/javascript"></script> 
	<script src="js/jquery.jqGrid.src.js" type="text/javascript"></script>
	<link href="css/ui.jqgrid.css" rel="stylesheet" type="text/css"/>

	<script src="js/sso-common.js" type="text/javascript"></script>
	<link href="./css/sso-common.css" rel="stylesheet" type="text/css"/>
	<link href="./css/sso-auditmail.css?v=1" rel="stylesheet" type="text/css"/>
</head>
<body>
	<div class="page-holder">
		<input type="hidden" id="adminid" value="<%=XSSCheck(adminid)%>"/>
		<input type="hidden" id="adminip" value="<%=XSSCheck(adminip)%>"/>
		<input type="hidden" id="currip" value="<%=XSSCheck(currip)%>"/>
		<input type="hidden" id="challenge" value="<%=XSSCheck(challenge)%>"/>

		<div class="page-breadcrumb">
			HOME / 감사 정책 / 메일 통보 설정
		</div>
		<div class="page-header">
			<h4 class="title">메일 통보 설정</h4>
		</div>

		<div class="content-box width-50p">
			<div class="content-top">
				<div class="float-left">
					<button class="subtitle-btn" type="button"></button>
					<span class="subtitle-text">메일 서버</span>
				</div>
				<div class="float-right">
					<button class="btn" type="button" id="mailServerTest">발송 테스트</button>
					<button class="btn ml-5" type="button" id="setMailServer">저 장</button>
				</div>
			</div>
			<div class="content-body pb-15">
				<table id="info">
					<colgroup>
						<col width="24%">
						<col width="76%">
					</colgroup>
					<tr>
						<td id="colnm">SMTP 서버</td>
						<td id="coldata">
							<input class="basic_input" type="text" id="smtpHost" maxlength="50"/>
						</td>
					</tr>
					<tr>
						<td id="colnm">SMTP 포트</td>
						<td id="coldata">
							<input class="basic_input" type="text" id="smtpPort" maxlength="10"/>
						</td>
					</tr>
					<tr>
						<td id="colnm">SMTP 보안연결</td>
						<td id="coldata">
							<div>
								<input type="radio" id="smtpTLS" name="smtpChnl" value="TLS" checked="checked" style="cursor:pointer;"/>
								<label for="smtpTLS" style="cursor:pointer; vertical-align:middle;">TLS</label>
								<input type="radio" id="smtpSSL" name="smtpChnl" value="SSL" style="cursor:pointer; margin-left:20px;"/>
								<label for="smtpSSL" style="cursor:pointer; vertical-align:middle;">SSL</label>
								<input type="radio" id="smtpMES" name="smtpChnl" value="MES" style="cursor:pointer; margin-left:20px;"/>
								<label for="smtpMES" style="cursor:pointer; vertical-align:middle;">Exchange Server</label>
							</div>
						</td>
					</tr>
					<tr>
						<td id="colnm"></td>
						<td id="coldata">
							<input type="checkbox" id="smtpAuth" checked="checked" style="cursor:pointer;"/>
							<label for="smtpAuth" style="cursor:pointer; vertical-align:middle;">&nbsp;인증 여부</label>
						</td>
					</tr>
					<tr>
						<td id="colnm">인증 이메일</td>
						<td id="coldata">
							<input class="basic_input" type="text" id="authId" maxlength="30"/>
						</td>
					</tr>
					<tr>
						<td class="tdlast" id="colnm">인증 비밀번호</td>
						<td class="tdlast" id="coldata">
							<input class="basic_input" type="password" id="authPw" maxlength="20"/>
						</td>
					</tr>
				</table>
			</div>
		</div>

		<div class="d-flex pt-20">
			<div class="content-box width-30p mr-10" style="height:fit-content;">
				<div class="content-top pb-15">
					<div class="float-left">
						<button class="subtitle-btn" type="button"></button>
						<span class="subtitle-text">메일 정보</span>
					</div>
				</div>
				<div class="content-body pb-15">
					<div class="radio_box">
						<input type="radio" id="mcode00" name="sendCode" value="MSND0000" checked="checked" style="cursor:pointer; height:28px;"/>
						<label for="mcode00" style="cursor:pointer; vertical-align:middle;">&nbsp;인증 기능 비활성화 알림</label><br/>
						<input type="radio" id="mcode02" name="sendCode" value="MSND0002" style="cursor:pointer; height:28px;"/>
						<label for="mcode02" style="cursor:pointer; vertical-align:middle;">&nbsp;암호모듈 자가시험 오류 알림</label><br/>
						<input type="radio" id="mcode01" name="sendCode" value="MSND0001" style="cursor:pointer; height:28px;"/>
						<label for="mcode01" style="cursor:pointer; vertical-align:middle;">&nbsp;SSO모듈 무결성 검증 오류 알림</label><br/>
						<input type="radio" id="mcode05" name="sendCode" value="MSND0005" style="cursor:pointer; height:28px;"/>
						<label for="mcode05" style="cursor:pointer; vertical-align:middle;">&nbsp;SSO 프로세스 검증 오류 알림</label><br/>
						<input type="radio" id="mcode03" name="sendCode" value="MSND0003" style="cursor:pointer; height:28px;"/>
						<label for="mcode03" style="cursor:pointer; vertical-align:middle;">&nbsp;감사정보 저장용량 임계치 초과 알림</label><br/>
						<input type="radio" id="mcode04" name="sendCode" value="MSND0004" style="cursor:pointer; height:28px;"/>
						<label for="mcode04" style="cursor:pointer; vertical-align:middle;">&nbsp;감사정보 저장소 포화상태 알림</label>
					</div>
				</div>
			</div>

			<div class="content-box width-70p ml-10">
				<div class="content-top">
					<div class="float-left">
						<button class="subtitle-btn" type="button"></button>
						<span class="subtitle-text">메일 상세 정보</span>
					</div>
					<div class="float-right">
						<button class="btn" type="button" id="mailSendTest">발송 테스트</button>
						<button class="btn ml-5" type="button" id="setMailSend">저 장</button>
					</div>
				</div>
				<div class="content-body pb-15">
					<table id="info">
						<colgroup>
							<col style="width:13%;">
							<col style="width:77%;">
						</colgroup>
						<tr>
							<td id="colnm">수신자</td>
							<td id="coldata">관리자</td>
						</tr>
						<tr>
							<td id="colnm">참조자</td>
							<td id="coldata">
								<input class="basic_input" type="text" id="referrer" maxlength="200"/>
							</td>
						</tr>
						<tr>
							<td id="colnm">제목</td>
							<td id="coldata">
								<input class="basic_input" type="text" id="subject" maxlength="100"/>
							</td>
						</tr>
						<tr style="height:259px;">
							<td class="tdlast" id="colnm">내용</td>
							<td class="tdlast" id="coldata">
								<textarea class="mail_body" id="content"></textarea>
							</td>
						</tr>
					</table>
				</div>
			</div>
		</div>
	</div>

<script type="text/javascript">
	$(document).ready(function(){
		checkAdmin();
		getMailServer();
	});

	$(window).ready(function() {
		$('#smtpHost').css('width', $('#smtpHost').parent().width() - 20);
		$('#smtpPort').css('width', $('#smtpPort').parent().width() - 20);
		$('#authId').css('width', $('#authId').parent().width() - 20);
		$('#authPw').css('width', $('#authPw').parent().width() - 20);

		$('#referrer').css('width', $('#referrer').parent().width() - 20);
		$('#subject').css('width', $('#subject').parent().width() - 20);
		$('#content').css('width', $('#content').parent().width() - 20);
	});

	$(window).resize(function(){
		$('#smtpHost').css('width', $('#smtpHost').parent().width() - 20);
		$('#smtpPort').css('width', $('#smtpPort').parent().width() - 20);
		$('#authId').css('width', $('#authId').parent().width() - 20);
		$('#authPw').css('width', $('#authPw').parent().width() - 20);

		$('#referrer').css('width', $('#referrer').parent().width() - 20);
		$('#subject').css('width', $('#subject').parent().width() - 20);
		$('#content').css('width', $('#content').parent().width() - 20);
	});

	function keydown(event)
	{
		parent.idleTime = new Date(); 

		// Refresh Key Check
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 116 || (event.ctrlKey && keyID == 82)) {  // 116=F5 82=Ctrl+r
			parent.f5key = true;
		}
	}
	$(document).on("keydown", keydown);

	function click()
	{
		parent.idleTime = new Date();
	}
	$(document).on("click", click);

	$("#smtpHost").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^a-z0-9.]/g, '');
		}
	});

	$("#smtpPort").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^0-9]/g, '');
		}
	});

	$("#authId").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^a-z0-9.@]/g, '');
		}
	});

	$("#referrer").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^a-z0-9.@;]/g, '');
		}
	});

	$("#setMailServer").click(function() {
		this.blur();
		var smtphost = XSSCheck($("#smtpHost").val().trim());
		var smtpport = $("#smtpPort").val().trim();
		var smtpchnl = $("input:radio[name='smtpChnl']:checked").val();
		var smtpauth = $("#smtpAuth").prop("checked") == true ? "Y" : "N";
		var authid = XSSCheck($("#authId").val().trim());
		var authpw = $("#authPw").val();
		var ch = $("#challenge").val();

		$("#smtpHost").val(smtphost);
		$("#smtpPort").val(smtpport);
		$("#authId").val(authid);

		if (smtphost == null || smtphost == "") {
			$("#smtpHost").focus();
			alert(" [SMTP 서버]  입력하세요.");
			return;
		}
		if (smtpport == null || smtpport == "") {
			$("#smtpPort").focus();
			alert(" [SMTP 포트]  입력하세요.");
			return;
		}
		if (authid == null || authid == "") {
			$("#authId").focus();
			alert(" [인증 이메일]  입력하세요.");
			return;
		}

		var nPort = parseInt(smtpport);
		if (nPort < 0 || nPort > 65535) {
			alert(" [SMTP 포트]  0 ~ 65535 사이의 정수값를 입력하세요.");
			$("#smtpPort").focus();
			return;
		}
		else {
			$("#smtpPort").val("" + nPort);
			smtpport = $("#smtpPort").val();
		}

		if (smtpauth == "Y" && (authpw == null || authpw == "")) {
			$("#authPw").focus();
			alert(" [인증 비밀번호]  입력하세요.");
			return;
		}

		if (!confirm(" [메일 서버]  저장하시겠습니까?"))
			return;

		$.ajax({
			type: "POST",
			url: "sub/setMailServer.jsp",
			data: {ch:ch, smtphost:smtphost, smtpport:smtpport, smtpchnl:smtpchnl, smtpauth:smtpauth, authid:authid, authpw:authpw},
			dataType: "JSON",
			async: false,
			success: function(data) {
				var resultstatus = data.rows[0].resultstatus;
				if (resultstatus == 1) {
					alert(" [메일 서버]  저장 완료");
				}
				else if (resultstatus == -9) {
					alert(" 로그인 후 사용하세요.");
					parent.location.href = "<%=XSSCheck(LOGIN_PAGE)%>";
				}
				else if (resultstatus == -8) {
					alert(" 처리 권한이 없습니다.");
					parent.location.href = "<%=XSSCheck(ADMIN_MAIN_PAGE)%>";
				}
				else {
					alert(" [메일 서버]  저장 오류 (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
				}
			},
			error: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});
	});

	$("#mailServerTest").click(function() {
		this.blur();
		var smtphost = XSSCheck($("#smtpHost").val().trim());
		var smtpport = $("#smtpPort").val().trim();
		var smtpchnl = $("input:radio[name='smtpChnl']:checked").val();
		var smtpauth = $("#smtpAuth").prop("checked") == true ? "Y" : "N";
		var authid = XSSCheck($("#authId").val().trim());
		var authpw = $("#authPw").val();

		$("#smtpHost").val(smtphost);
		$("#smtpPort").val(smtpport);
		$("#authId").val(authid);

		if (smtphost == null || smtphost == "") {
			$("#smtpHost").focus();
			alert(" [SMTP 서버]  입력하세요.");
			return;
		}
		if (smtpport == null || smtpport == "") {
			$("#smtpPort").focus();
			alert(" [SMTP 포트]  입력하세요.");
			return;
		}
		if (authid == null || authid == "") {
			$("#authId").focus();
			alert(" [인증 이메일]  입력하세요.");
			return;
		}

		var nPort = parseInt(smtpport);
		if (nPort < 0 || nPort > 65535) {
			alert(" [SMTP 포트]  0 ~ 65535 사이의 정수값를 입력하세요.");
			$("#smtpPort").focus();
			return;
		}

		if (smtpauth == "Y" && (authpw == null || authpw == "")) {
			$("#authPw").focus();
			alert(" [인증 비밀번호]  입력하세요.");
			return;
		}

		if (!confirm(" [메일 서버]  발송 테스트 하시겠습니까?"))
			return;

		$.ajax({
			type: "POST",
			url: "sub/mailServerTest.jsp",
			data: {smtphost:smtphost, smtpport:smtpport, smtpchnl:smtpchnl, smtpauth:smtpauth, authid:authid, authpw:authpw},
			dataType: "JSON",
			async: false,
			success: function(data) {
				var resultstatus = data.rows[0].resultstatus;
				if (resultstatus == 1) {
					alert(" [메일 서버]  발송 테스트 성공");
				}
				else if (resultstatus == -9) {
					alert(" 로그인 후 사용하세요.");
					parent.location.href = "<%=XSSCheck(LOGIN_PAGE)%>";
				}
				else if (resultstatus == -8) {
					alert(" 처리 권한이 없습니다.");
					parent.location.href = "<%=XSSCheck(ADMIN_MAIN_PAGE)%>";
				}
				else {
					alert(" [메일 서버]  발송 테스트 실패 (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
				}
			},
			error: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});
	});

	$("#setMailSend").click(function() {
		this.blur();
		var code = $("input:radio[name='sendCode']:checked").val();
		var referrer = XSSCheck($("#referrer").val().trim());
		var subject = XSSCheck($("#subject").val().trim());
		var content = XSSCheck($("#content").val());
		var ch = $("#challenge").val();

		$("#referrer").val(referrer);
		$("#subject").val(subject);

		if (referrer != "") {
			var arrStr = referrer.split(";");
			var newStr = "";

			for (var i = 0; i < arrStr.length; i++) {
				if (arrStr[i] != null && arrStr[i] != "")
					newStr += arrStr[i].trim() + "; ";
			}

			referrer = newStr.trim();
			$("#referrer").val(referrer);
		}

		if (subject == "") {
			$("#subject").focus();
			alert(" [제목]  입력하세요.");
			return;
		}
		if (content == "") {
			$("#content").focus();
			alert(" [내용]  입력하세요.");
			return;
		}

		if (content.length > 500) {
			$("#content").focus();
	        alert(" 메일 내용은 500자 이내로 제한됩니다.");
	        return;
	    }

		if (!confirm(" [메일 정보]  저장하시겠습니까?"))
			return;

		$.ajax({
			type: "POST",
			url: "sub/setMailSend.jsp",
			data: {ch:ch, code:code, referrer:referrer, subject:subject, content:content},
			dataType: "JSON",
			async: false,
			success: function(data) {
				var resultstatus = data.rows[0].resultstatus;
				if (resultstatus == 1) {
					alert(" [메일 정보]  저장 완료");
				}
				else if (resultstatus == -9) {
					alert(" 로그인 후 사용하세요.");
					parent.location.href = "<%=XSSCheck(LOGIN_PAGE)%>";
				}
				else if (resultstatus == -8) {
					alert(" 처리 권한이 없습니다.");
					parent.location.href = "<%=XSSCheck(ADMIN_MAIN_PAGE)%>";
				}
				else {
					alert(" [메일 정보]  저장 오류 (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
				}
			},
			error: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});
	});

	$("#mailSendTest").click(function() {
		this.blur();
		var referrer = XSSCheck($("#referrer").val().trim());
		var subject = XSSCheck($("#subject").val().trim());
		var content = XSSCheck($("#content").val());

		$("#referrer").val(referrer);
		$("#subject").val(subject);

		if (referrer != "") {
			var arrStr = referrer.split(";");
			var newStr = "";

			for (var i = 0; i < arrStr.length; i++) {
				if (arrStr[i] != null && arrStr[i] != "")
					newStr += arrStr[i].trim() + "; ";
			}

			referrer = newStr.trim();
			$("#referrer").val(referrer);
		}

		if (subject == "") {
			$("#subject").focus();
			alert(" [제목] 입력하세요.");
			return;
		}

		if (content == "") {
			$("#content").focus();
			alert(" [내용] 입력하세요.");
			return;
		}

		if (content.length > 500) {
			$("#content").focus();
	        alert(" 메일 본문 내용은 500자 이내로 제한됩니다.");
	        return;
	    }

		if (!confirm(" [메일 정보]  발송 테스트 하시겠습니까?"))
			return;

		$.ajax({
			type: "POST",
			url: "sub/mailSendTest.jsp",
			data: {referrer:referrer, subject:subject, content:content},
			dataType: "JSON",
			async: false,
			success: function(data) {
				var resultstatus = data.rows[0].resultstatus;
				if (resultstatus == 1) {
					alert(" [메일 정보]  발송 테스트 성공");
				}
				else if (resultstatus == -9) {
					alert(" 로그인 후 사용하세요.");
					parent.location.href = "<%=XSSCheck(LOGIN_PAGE)%>";
				}
				else if (resultstatus == -8) {
					alert(" 처리 권한이 없습니다.");
					parent.location.href = "<%=XSSCheck(ADMIN_MAIN_PAGE)%>";
				}
				else {
					alert(" [메일 정보]  발송 테스트 실패 (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
				}
			},
			error: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});
	});

	$("#smtpHost").keydown(function(e) {
		if (e.keyCode == 13)
			$("#smtpPort").focus();
	});
	$("#smtpPort").keydown(function(e) {
		if (e.keyCode == 13)
			$("#authId").focus();
	});
	$("#authId").keydown(function(e) {
		if (e.keyCode == 13)
			$("#authPw").focus();
	});

	$("#referrer").keydown(function(e) {
		if (e.keyCode == 13)
			$("#subject").focus();
	});
	$("#subject").keydown(function(e) {
		if (e.keyCode == 13) {
			$("#content").focus();
			return false;
		}
	});

	$("#content").keypress(function(e) {
	    var lengthF = $(this).val();

	    if (lengthF.length >= 500) {
	        alert(" 메일 본문 내용은 500자 이내로 제한됩니다.");
	        return false;
	    }
	});

	$("input[type='radio'][name='sendCode']").change(function () {
        getMailSend(this.value);
    });

	function getMailServer()
	{
		$.ajax({
			type: "POST",
			url: "sub/getMailServer.jsp",
			data: {},
			dataType: "JSON",
			async: false,
			success: function(data) {
				if (data != null && data.rows.length == 1) {
					var result = data.rows[0];
					$("#smtpHost").val(result.smtpHost);
					$("#smtpPort").val(result.smtpPort);
					$("input:radio[name='smtpChnl'][value='"+ result.smtpChnl +"']").prop("checked", true);

					if (result.smtpAuth == "Y")
						$("#smtpAuth").prop("checked", true);
					else
						$("#smtpAuth").prop("checked", false);

					$("#authId").val(result.authId);
					$("#authPw").val(result.authPw);
				}

				getMailSend("MSND0000");
			},
			error: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});
	}

	function getMailSend(code)
	{
		$.ajax({
			type: "POST",
			url: "sub/getMailSend.jsp",
			data: {code:code},
			dataType: "JSON",
			async: false,
			success: function(data) {
				if (data != null && data.rows.length == 1) {
					var result = data.rows[0];
					$("#referrer").val(result.referrer);
					$("#subject").val(result.subject);
					$("#content").val(result.content);
				}
			},
			error: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});
	}

</script>
</body>
</html>
