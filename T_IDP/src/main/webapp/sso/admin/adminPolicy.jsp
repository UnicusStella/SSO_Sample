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
	<link href="./css/sso-adminpolicy.css?v=2" rel="stylesheet" type="text/css"/>
</head>
<body>
	<div class="page-holder">
		<input type="hidden" id="adminid" value="<%=XSSCheck(adminid)%>"/>
		<input type="hidden" id="admintype" value="<%=XSSCheck(admintype)%>"/>
		<input type="hidden" id="adminip" value="<%=XSSCheck(adminip)%>"/>
		<input type="hidden" id="currip" value="<%=XSSCheck(currip)%>"/>
		<input type="hidden" id="challenge" value="<%=XSSCheck(challenge)%>"/>
		<input type="hidden" id="pwAllow" value="5"/>
		<input type="hidden" id="authLockTime" value="5"/>
		<input type="hidden" id="sessTime" value="10"/>
		<input type="hidden" id="maxCount" value="2"/>

		<div class="page-breadcrumb">
			HOME / ????????? / ????????? ??????
		</div>
		<div class="page-header">
			<h4 class="title">????????? ??????</h4>
		</div>

		<div class="d-flex">
			<div class="content-box width-50p mr-10" style="height:fit-content;">
				<div class="content-top">
					<div class="float-left">
						<button class="subtitle-btn" type="button"></button>
						<span class="subtitle-text">????????? ?????? ??????</span>
					</div>
					<div class="float-right">
						<button class="btn" type="button" id="getAdpy">?????????</button>
						<button class="btn ml-5" type="button" id="setAdpy">??? ???</button>
					</div>
				</div>
				<div class="content-body pb-15">
					<table id="info">
						<colgroup>
							<col style="width:35%;">
							<col style="width:65%;">
						</colgroup>
						<tr>
							<td id="colnm">???????????? ?????? ?????? ??????</td>
							<td id="coldata">
								<input class="right_input" type="text" id="pwMismatchAllow" style="width:60px;" maxlength="2"/>&nbsp;??? ?????? ????????? ????????? ??????
							</td>
						</tr>
						<tr>
							<td id="colnm">????????? ?????? ??????</td>
							<td id="coldata">
								<input class="right_input" type="text" id="lockTime" style="width:60px;" maxlength="2"/>&nbsp;??? ?????? ????????? ??????
							</td>
						</tr>
						<tr>
							<td id="colnm">?????? ????????? ??????</td>
							<td id="coldata">
								<input class="right_input" type="text" id="sessionTime" style="width:60px;" maxlength="4"/>&nbsp;??? ?????? ???????????? ????????????
							</td>
						</tr>
						<tr>
							<td class="tdlast" id="colnm">?????? IP ?????? ??????</td>
							<td class="tdlast" id="coldata">
								<input class="right_input" type="text" id="ipCount" style="width:60px;" maxlength="2"/>&nbsp;?????? ??????
							</td>
						</tr>
					</table>
				</div>
			</div>
	
			<div class="content-box width-50p ml-10">
				<div class="content-top">
					<div class="float-left">
						<button class="subtitle-btn" type="button"></button>
						<span class="subtitle-text">?????? IP ?????????</span>
					</div>
					<div class="float-right">
						<input class="rept_input" type="text" id="inputIp" style="width:160px;" placeholder="?????? IP"/>
						<button class="btn ml-5" type="button" id="newAdmnIp">??? ???</button>
						<button class="btn ml-5" type="button" id="removeAdmnIp">??? ???</button>
					</div>
				</div>
				<div class="content-body pb-15" id="list-box">
					<table id="admnIpList"></table>
				</div>
			</div>
		</div>
	</div>

<script type="text/javascript">
	var loadAdpy = true;

	$(document).ready(function(){
		checkAdmin();

		$("#admnIpList").jqGrid({
			url: "sub/getAdminIpList.jsp",
			datatype: "json",
			colNames: ['?????? IP'],
		    colModel: [
		        {name:'ip', index:'ip', width:'100%', align:'center', sortable:false}
			],
			id: 'ip',
		    rowNum: 1000000,
		    rownumbers: true,
		    gridview: true,
			scrollrows: true,
			loadonce: true,
			sortable: true,
			sortname: 'ip',
			sortorder: 'asc',
		    height: 521,
		    loadtext: 'Loading...',
		    loadComplete:function(){
				$('#admnIpList').setGridWidth($('#list-box').width(), true);

				if (loadAdpy) {
					getAdpyInfo();
					loadAdpy = false;
				}
		    },
			loadError: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		}).setGridWidth($('#list-box').width(), true);

		setTimeout(ipListSort, 100);
	});

	$(window).on('load', function(){
	});

	$(window).resize(function(){
		$('#admnIpList').setGridWidth($('#list-box').width(), true);
	});

	function ipListSort()
	{
		$("#admnIpList").setGridParam({datatype:"local"}).trigger("reloadGrid");
	}

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

	$("#newAdmnIp").click(function() {
		this.blur();
		var inputip = $("#inputIp").val();
		var ch = $("#challenge").val();

		if (inputip == "") {
			alert(" ?????? IP??? ???????????????.");
			$("#inputIp").focus();
			return;
		}

		listcnt = $("#admnIpList").getGridParam("reccount");
		maxcnt = parseInt($("#maxCount").val());
		if (listcnt == maxcnt) {
			alert(" ?????? IP??? ??? ?????? ????????? ??? ????????????.");
			return;
		}

		format = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/;
		if (!format.test(inputip)) {
			alert(" ?????? IP??? ????????? ?????? ???????????????.");
			$("#inputIp").focus();
			return;
		}

		if (inputip == "127.0.0.1") {
			alert(" [ " + inputip + " ]  ????????? ??? ?????? IP ?????????.");
			$("#inputIp").focus();
			return;
		}

		var arrayIp = inputip.split(".");
		if (arrayIp[3] == '0' || arrayIp[3] == '255') {
			alert(" [ " + inputip + " ]  ????????? ??? ?????? IP ?????????.");
			$("#inputIp").focus();
			return;
		}

		var list = $("#admnIpList").getDataIDs();
		for (var i = 0; i < list.length; i++) {
			row = $("#admnIpList").getRowData(list[i]);
			if (row.ip == inputip) {
				$("#admnIpList").setSelection(list[i]);
				alert(" [ " + inputip +" ]  ????????? IP ?????????.");
				$("#inputIp").focus();
				return;
			}
		}

		if (!confirm(" [ " + inputip +" ]  ?????? IP??? ?????????????????????????"))
			return;

		$.ajax({
			type: "POST",
			url: "sub/setAdminIp.jsp",
			data: {ch:ch, ip:inputip},
			dataType: "JSON",
			async: false,
			success: function(data) {
				var resultstatus = data.rows[0].resultstatus;
				if (resultstatus == 1) {
					$("#inputIp").val("");
					var newRowData = {'ip': inputip};
      				$("#admnIpList").addRowData(inputip, newRowData, "last");
					$("#admnIpList").setGridParam({datatype:'local'}).trigger("reloadGrid");
					alert(" ?????? ??????");
				}
				else if (resultstatus == -9) {
					alert(" ????????? ??? ???????????????.");
					parent.location.href = "<%=XSSCheck(LOGIN_PAGE)%>";
				}
				else if (resultstatus == -8) {
					alert(" ?????? ????????? ????????????.");
					parent.location.href = "<%=XSSCheck(ADMIN_MAIN_PAGE)%>";
				}
				else {
					alert(" IP: " + inputip + " ?????? ?????? (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
				}
			},
			error: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});
	});

	$("#removeAdmnIp").click(function() {
		this.blur();
		var id = $("#admnIpList").getGridParam("selrow");
		var row = $("#admnIpList").getRowData(id);
		var ch = $("#challenge").val();

		if (row.ip == "" || row.ip == null) {
			alert(" ?????? IP??? ???????????????.");
			return;
		}

		if ($("#adminip").val() == row.ip) {
			alert(" ?????? ?????? IP??? ????????? ??? ????????????.");
			return;
		}

		if (confirm(" [ " + row.ip + " ]  ?????? IP??? ?????????????????????????")) {
			$.ajax({
				type: "POST",
				url: "sub/removeAdminIp.jsp",
				data: {ch:ch, ip:row.ip},
				dataType: "JSON",
				async: false,
				success: function(data) {
					var resultstatus = data.rows[0].resultstatus;
					if (resultstatus == 1) {
						$("#admnIpList").delRowData(id);
						$("#admnIpList").setGridParam({datatype:"local"}).trigger("reloadGrid");
						alert(" ?????? ??????");
					}
					else if (resultstatus == -9) {
						alert(" ????????? ??? ???????????????.");
						parent.location.href = "<%=XSSCheck(LOGIN_PAGE)%>";
					}
					else if (resultstatus == -8) {
						alert(" ?????? ????????? ????????????.");
						parent.location.href = "<%=XSSCheck(ADMIN_MAIN_PAGE)%>";
					}
					else {
						alert(" IP: " + row.ip + " ?????? ?????? (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
					}
				},
				error: function(xhr, status, error) {
					ajaxerror(xhr, status, error);
				}
			});
		}
	});

	$("#getAdpy").click(function(){
		this.blur();
		$("#pwMismatchAllow").val($("#pwAllow").val());
		$("#lockTime").val($("#authLockTime").val());
		$("#sessionTime").val($("#sessTime").val());
		$("#ipCount").val($("#maxCount").val());
	});

	$("#setAdpy").click(function(){
		this.blur();
		var pwallow = $("#pwMismatchAllow").val();
		var locktime = $("#lockTime").val();
		var sesstime = $("#sessionTime").val();
		var ipcnt = $("#ipCount").val();
		var ch = $("#challenge").val();

		if (pwallow == null || pwallow == "") {
			alert(" [???????????? ?????? ?????? ??????]  ???????????????.");
			$("#pwMismatchAllow").focus();
			return;
		}

		var nPwallow = parseInt(pwallow);
		if (nPwallow < 1 || nPwallow > 5) {
			alert(" ???????????? ?????? ?????? ????????? 1 ~ 5 ????????? ???????????? ???????????????.");
			$("#pwMismatchAllow").focus();
			return;
		}
		else {
			$("#pwMismatchAllow").val("" + nPwallow);
			pwallow = $("#pwMismatchAllow").val();
		}

		if (locktime == null || locktime == "") {
			alert(" [????????? ?????? ??????]  ???????????????.");
			$("#lockTime").focus();
			return;
		}

		var nLocktime = parseInt(locktime);
		if (nLocktime < 5 || nLocktime > 10) {
			alert(" ????????? ?????? ????????? 5 ~ 10 ????????? ???????????? ???????????????.");
			$("#lockTime").focus();
			return;
		}
		else {
			$("#lockTime").val("" + nLocktime);
			locktime = $("#lockTime").val();
		}

		if (sesstime == null || sesstime == "") {
			alert(" [?????? ????????? ??????]  ???????????????.");
			$("#sessionTime").focus();
			return;
		}

		var nSesstime = parseInt(sesstime);
		if (nSesstime < 3 || nSesstime > 10) {
			alert(" ?????? ????????? ????????? 3 ~ 10 ????????? ???????????? ???????????????.");
			$("#sessionTime").focus();
			return;
		}
		else {
			$("#sessionTime").val("" + nSesstime);
			sesstime = $("#sessionTime").val();
		}

		if (ipcnt == null || ipcnt == "") {
			alert(" [?????? IP ?????? ??????]  ???????????????.");
			$("#ipCount").focus();
			return;
		}

		var nIpcnt = parseInt(ipcnt);
		if (nIpcnt < 2 || nIpcnt > 99) {
			alert(" ?????? IP ?????? ????????? 2 ~ 99 ????????? ???????????? ???????????????.");
			$("#ipCount").focus();
			return;
		}
		else {
			$("#ipCount").val("" + nIpcnt);
			ipcnt = $("#ipCount").val();
		}

		listcnt = $("#admnIpList").getGridParam("reccount");
		if (listcnt > nIpcnt) {
			alert(" ????????? ?????? IP ????????? ?????? ????????? ??? ????????????.");
			$("#ipCount").focus();
			return;
		}

		if (!confirm(" ????????? ????????? ?????????????????????????"))
			return;

		$.ajax({
			type: "POST",
			url: "sub/setAdpyInfo.jsp",
			data: {ch:ch, code:"ADPY0001", pwallow:pwallow, locktime:locktime, sesstime:sesstime, ipcnt:ipcnt},
			dataType: "JSON",
			async: false,
			success: function(data) {
				var resultstatus = data.rows[0].resultstatus;
				if (resultstatus == 1) {
					$("#pwAllow").val(pwallow);
					$("#authLockTime").val(locktime);
					$("#sessTime").val(sesstime);
					$("#maxCount").val(ipcnt);
					alert(" ?????? ??????");
				}
				else if (resultstatus == -9) {
					alert(" ????????? ??? ???????????????.");
					parent.location.href = "<%=XSSCheck(LOGIN_PAGE)%>";
				}
				else if (resultstatus == -8) {
					alert(" ?????? ????????? ????????????.");
					parent.location.href = "<%=XSSCheck(ADMIN_MAIN_PAGE)%>";
				}
				else {
					alert(" ????????? ?????? ?????? ?????? (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
				}
			},
			error: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});
	});

	$("#inputIp").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^0-9.]/g, '');
		}
	});
	$("#pwMismatchAllow").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^0-9]/g, '');
		}
	});
	$("#lockTime").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^0-9]/g, '');
		}
	});
	$("#sessionTime").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^0-9]/g, '');
		}
	});
	$("#ipCount").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^0-9]/g, '');
		}
	});

	function getAdpyInfo()
	{
		$.ajax({
			type: "POST",
			url: "sub/getAdpyInfo.jsp",
			data: {code: "ADPY0001"},
			dataType: "JSON",
			async: false,
			success: function(data) {
				if (data != null && data.rows.length == 1) {
					var result = data.rows[0];
					$("#pwMismatchAllow").val(result.pwMismatchAllow);
					$("#lockTime").val(result.lockTime);
					$("#sessionTime").val(result.sessionTime);
					$("#ipCount").val(result.ipMaxCount);

					$("#pwAllow").val(result.pwMismatchAllow);
					$("#authLockTime").val(result.lockTime);
					$("#sessTime").val(result.sessionTime);
					$("#maxCount").val(result.ipMaxCount);
				}
				else {
					alert(" ?????? ??????");
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