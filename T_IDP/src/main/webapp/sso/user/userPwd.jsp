<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ page import="com.dreamsecurity.sso.server.api.admin.AdminController"%>
<%!
	public String XSSCheck(String value)
	{
		if (value != null && value.trim().length() > 0) {
			value = value.trim();
			value = value.replaceAll("<", "&lt;");
			value = value.replaceAll(">", "&gt;");
			value = value.replaceAll("&", "&amp;");
			value = value.replaceAll("\"", "&quot;");
			value = value.replaceAll("\'", "&apos;");
		}

		return value;
	}
%>
<%
	String userid = (String) session.getAttribute("SSO_ID");

	AdminController adminApi = new AdminController();
	String challenge = adminApi.createAdminCSRFToken(request);
%>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
<head>
	<meta http-equiv="Content-Style-Type" content="text/css"/>
	<meta http-equiv="X-UA-Compatible" content="IE=8"/>

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

	<link href="./css/sso-common.css" rel="stylesheet" type="text/css"/>
	<link href="./css/sso-userpwd.css" rel="stylesheet" type="text/css"/>
</head>
<body>
	<input type="hidden" id="userid" value="<%=XSSCheck(userid)%>"/>
	<input type="hidden" id="challenge" value="<%=XSSCheck(challenge)%>"/>

	<div class="content">
		<div class="title_box">
			<p class="title"><strong>&nbsp;비밀번호 변경</strong></p>
			<p class="path">HOME &gt; <span class="path2">사용자</span> &gt; <strong>비밀번호 변경</strong></p>
		</div>
		<div class="content_box">
			<div class="subtitle_box">
				<button class="subtitle_btn" type="button"></button>
				<span class="subtitle_text">비밀번호 변경</span>
				<div class="btn_right_align">
					<button class="button_base" type="button" id="setUserPwd" style="margin-left:5px;">저장</button>
				</div>
			</div>
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
			<div class="alert">
				###&nbsp;&nbsp;&nbsp;비밀번호는 9 ~ 16자의 영문자, 숫자, 특수문자(!@#$%^*+=-)를 조합하여 사용합니다.&nbsp;&nbsp;&nbsp;###
			</div>
		</div>
    </div>

<script type="text/javascript">
	$(document).ready(function(){
	});

	$(window).on('load', function(){
		$('#curPwd').css('width', $('#curPwd').parent().width()-20);
		$('#newPwd').css('width', $('#newPwd').parent().width()-20);
		$('#chkPwd').css('width', $('#chkPwd').parent().width()-20);
	});

	$(window).resize(function(){
		$('#curPwd').css('width', $('#curPwd').parent().width()-20);
		$('#newPwd').css('width', $('#newPwd').parent().width()-20);
		$('#chkPwd').css('width', $('#chkPwd').parent().width()-20);
	});

	function keydown(e) { if ((e.which || e.keyCode) == 116) parent.before = true; }
	$(document).on("keydown", keydown);

	$("#setUserPwd").click(function() {
		this.blur();
		var uid = $("#userid").val();
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
			url: "sub/setUserPwd.jsp",
			data: {ch:ch, uid:uid, curpwd:curpwd, newpwd:newpwd},
			dataType: "JSON",
			async: false,
			success: function(data) {
				var resultstatus = data.rows[0].resultstatus;
				if (resultstatus == 1) {
					$("#curPwd").val("");
					$("#newPwd").val("");
					$("#chkPwd").val("");
					alert(" 저장 완료");
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
