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
	<link href="./css/sso-userpwd.css?v=1" rel="stylesheet" type="text/css"/>
</head>
<body>
	<div class="page-holder">
		<input type="hidden" id="adminid" value="<%=XSSCheck(adminid)%>"/>
		<input type="hidden" id="adminfirst" value="<%=XSSCheck(adminfirst)%>"/>
		<input type="hidden" id="adminip" value="<%=XSSCheck(adminip)%>"/>
		<input type="hidden" id="currip" value="<%=XSSCheck(currip)%>"/>
		<input type="hidden" id="challenge" value="<%=XSSCheck(challenge)%>"/>

		<div class="page-breadcrumb">
			HOME / 관리자 / 비밀번호 변경
		</div>
		<div class="page-header">
			<h4 class="title">비밀번호 변경</h4>
		</div>

		<div class="content-box width-60p">
			<div class="content-top">
				<div class="float-left">
					<button class="subtitle-btn" type="button"></button>
					<span class="subtitle-text">비밀번호 변경</span>
				</div>
				<div class="float-right">
					<button class="btn" type="button" id="setUserPwd">저 장</button>
				</div>
			</div>
			<div class="content-body">
				<table id="info">
					<colgroup>
						<col width="30%"/>
						<col width="70%"/>
					</colgroup>
					<tr>
						<td id="colnm">현재 비밀번호</td>
						<td id="coldata">
							<input class="basic_input" type="password" id="curPwd" maxlength="16"/>
						</td>
					</tr>
					<tr>
						<td id="colnm">새 비밀번호</td>
						<td id="coldata">
							<input class="basic_input" type="password" id="newPwd" maxlength="16"/>
						</td>
					</tr>
					<tr>
						<td class="tdlast" id="colnm">새 비밀번호 확인</td>
						<td class="tdlast" id="coldata">
							<input class="basic_input" type="password" id="chkPwd" maxlength="16"/>
						</td>
					</tr>
				</table>
			</div>
			<div class="content-bottom">
				<div class="cont-bottom-left alert">
				###&nbsp;&nbsp;&nbsp;비밀번호는 9 ~ 16자의 영문자, 숫자, 특수문자(!@#$%^*+=-)를 조합하여 사용합니다.&nbsp;&nbsp;&nbsp;###
				</div>
			</div>
		</div>
	</div>

<script type="text/javascript">
	$(document).ready(function(){
		checkAdmin();
	});

	$(document).ready(function() {
		$('#curPwd').css('width', $('#curPwd').parent().width()-20);
		$('#newPwd').css('width', $('#newPwd').parent().width()-20);
		$('#chkPwd').css('width', $('#chkPwd').parent().width()-20);
	});

	$(window).resize(function(){
		$('#curPwd').css('width', $('#curPwd').parent().width()-20);
		$('#newPwd').css('width', $('#newPwd').parent().width()-20);
		$('#chkPwd').css('width', $('#chkPwd').parent().width()-20);
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

	$("#setUserPwd").click(function() {
		this.blur();
		var uid = $("#adminid").val();
		var curpwd = $("#curPwd").val();
		var newpwd = $("#newPwd").val();
		var chkpwd = $("#chkPwd").val();
		var ch = $("#challenge").val();

		if (curpwd == null || curpwd == "") {
			alert(" [현재 비밀번호]  입력하세요.");
			$("#curPwd").focus();
			return;
		}
		if (newpwd == null || newpwd == "") {
			alert(" [새 비밀번호]  입력하세요.");
			$("#newPwd").focus();
			return;
		}
		if (chkpwd == null || chkpwd == "") {
			alert(" [새 비밀번호 확인]  입력하세요.");
			$("#chkPwd").focus();
			return;
		}

		format = /^(?=.*[a-zA-Z])(?=.*[!@#$%^*+=-])(?=.*[0-9]).{9,16}$/;
		if (!format.test(newpwd)) {
			alert(" [새 비밀번호]를 규칙에 맞게 입력하세요.");
			$("#newPwd").focus();
			return;
		}

		if (newpwd != chkpwd) {
			alert(" [새 비밀번호]와  [새 비밀번호 확인]이 일치하지 않습니다.");
			$("#chkPwd").focus();
			return;
		}

		if (newpwd == curpwd) {
			alert(" [현재 비밀번호]와  [새 비밀번호]가 동일합니다.");
			$("#newPwd").focus();
			return;
		}

		$.ajax({
			type: "POST",
			url: "sub/setAdminPwd.jsp",
			data: {ch:ch, uid:uid, curpwd:curpwd, newpwd:newpwd},
			dataType: "JSON",
			async: false,
			success: function(data) {
				var resultstatus = data.rows[0].resultstatus;
				if (resultstatus == 1) {
					if ($("#adminfirst").val() == "Y") {
						$("#adminfirst").val("");
						$("#adminfirst", parent.document.body).val("");
					}
					$("#curPwd").val("");
					$("#newPwd").val("");
					$("#chkPwd").val("");
					alert(" 저장 완료");
				}
				else if (resultstatus == -9) {
					alert(" 로그인 후 사용하세요.");
					parent.location.href = "<%=XSSCheck(LOGIN_PAGE)%>";
				}
				else {
					alert(" 저장 실패 (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
				}
			},
			error: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});
	});

	$("#curPwd").keydown(function(e) {
		if (e.keyCode == 13)
			$("#newPwd").focus();
	});
	$("#newPwd").keydown(function(e) {
		if (e.keyCode == 13)
			$("#chkPwd").focus();
	});

</script>
</body>
</html>
