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

	<script src="js/sso-common.js" type="text/javascript"></script>
	<link href="./css/sso-common.css" rel="stylesheet" type="text/css"/>
	<link href="./css/sso-userinfo.css?a=1" rel="stylesheet" type="text/css"/>
</head>
<body>
	<input type="hidden" id="adminid" value="<%=XSSCheck(adminid)%>"/>
	<input type="hidden" id="adminip" value="<%=XSSCheck(adminip)%>"/>
	<input type="hidden" id="currip" value="<%=XSSCheck(currip)%>"/>
	<input type="hidden" id="challenge" value="<%=XSSCheck(challenge)%>"/>
	<input type="hidden" id="newflag" value="U">
	<input type="hidden" id="getInfoflag" value=-1>
	<input type="hidden" id="checkid" value=""/>
	<input type="hidden" id="curPage" value="1"/>
	<input type="hidden" id="pageRow" value="20"/>

	<div class="content">
		<div class="title_box">
			<p class="title">&nbsp;????????? ??????</p>
			<p class="path">HOME &gt; ????????? &gt; <span class="path2">????????? ??????</span></p>
		</div>
		<div class="content_box">
			<table id="side_box">
				<tr>
					<td id="side_left">
						<div class="subtitle_box">
							<button class="subtitle_btn" type="button"></button>
							<span class="subtitle_text">????????? ?????????</span>
							<div class="btn_right_align">
								<input class="search_input" type="text" id="searchName" style="width:160px;" placeholder="?????? ??????"/>
								<button class="button_base" type="button" id="removeUser" style="margin-left:5px;">??????</button>
							</div>
						</div>
						<div class="grid_box">
							<table id="userList"></table>
						</div>
						<div class="foot_page_box">
							<table class="ui-pg-table" style="table-layout:auto; margin:auto" border="0" cellspacing="0" cellpadding="0">
								<tr>
									<td class="ui-pg-button ui-corner-all" id="first_pager" style="cursor:pointer;">
										<span class="ui-icon ui-icon-seek-first"></span>
									</td>
									<td style="width:4px;"></td>
									<td class="ui-pg-button ui-corner-all" id="prev_pager" style="cursor:pointer;">
										<span class="ui-icon ui-icon-seek-prev"></span>
									</td>
									<td style="width:4px;"></td>
									<td>
										?????????
										<input class="pager_input" type="text" id="cur_pager" maxlength="4" style="ime-mode:inactive;"/>&nbsp;/
										<span id="total_pager"></span>
									</td>
									<td style="width:4px;"></td>
									<td class="ui-pg-button ui-corner-all" id="next_pager" style="cursor:pointer;">
										<span class="ui-icon ui-icon-seek-next"></span>
									</td>
									<td style="width:4px;"></td>
									<td class="ui-pg-button ui-corner-all" id="last_pager" style="cursor:pointer;">
										<span class="ui-icon ui-icon-seek-end"></span>
									</td>
									<td style="width:15px;"></td>
									<td style="width:60px;"><div id="total_count"></div></td>
								</tr>
							</table>
						</div>
					</td>
					<td id="side_right">
						<div class="subtitle_box">
							<button class="subtitle_btn" type="button"></button>
							<span class="subtitle_text">????????? ??????</span>
							<div class="btn_right_align">
								<button class="button_base" type="button" id="newUser">??????</button>
								<button class="button_base" type="button" id="setUser" style="margin-left:5px;">??????</button>
							</div>
						</div>
						<table id="info">
							<colgroup>
								<col style="width:22%;">
								<col style="width:78%;">
							</colgroup>
							<tr>
								<td id="colnm">??????</td>
								<td id="coldata">
									<input class="basic_input" type="text" id="userName" maxlength="50" style="ime-mode:active"/>
								</td>
							</tr>
							<tr>
								<td id="colnm">?????????</td>
								<td id="coldata">
									<input class="basic_input" type="text" id="userId" maxlength="16" style="margin-right:5px; ime-mode:inactive"/>
									<button class="button_small" type="button" id="checkUID">????????????</button>
								</td>
							</tr>
							<tr>
								<td id="colnm">????????????</td>
								<td id="coldata">
									<input class="basic_input" type="password" id="newPwd" maxlength="16"/>
								</td>
							</tr>
							<tr>
								<td class="tdlast" id="colnm">???????????? ??????</td>
								<td class="tdlast" id="coldata">
									<input class="basic_input" type="password" id="chkPwd" maxlength="16"/>
								</td>
							</tr>
						</table>
					</td>
				</tr>
			</table>
		</div>
    </div>

<script type="text/javascript">
	$(document).ready(function(){
		checkAdmin();

		clearUserInfo();
		$("#newflag").val("N");

		$("#userList").jqGrid({
			datatype: "local",
			jsonReader: {
				page: "page",
				total: "total",
				root: "rows",
				records: function(obj) {return obj.length;},
				repeatitems: false,
				id: "id"
			},
			colNames: ['??????', '?????????'],
		    colModel: [
				{name:'name', index:'name', width:'35%', align:'center', sortable:false},
				{name:'id', index:'id', width:'40%', align:'center', sortable:false}
			],
			id: 'id',
		    rowNum: 1000000,
		    gridview: true,
		    height: 521,
		    loadtext: 'Loading...',
			onSelectRow: function() {
				if ($("#getInfoflag").val() == -1)
					getUserInfo();
				else
					$("#getInfoflag").val(-1);
			},
		    loadComplete:function(data){
				$('#userList').setGridWidth(0, true);
				$('#userList').setGridWidth($('.grid_box').width(), true);

				var ids = $("#userList").getDataIDs();
				if (ids.length > 0) {
					$("#curPage").val(data.page)
					setPageTag(data.total, data.page);
				}
				else {
					setPageTag(0, 1);
				}

				var code = $("#userId").val();
				if (code != "" && code != null) {
					if ($("#userList").getInd(code) != false) {
						$("#getInfoflag").val(9);
						$("#userList").setSelection(code);
					}
				}
		    },
			loadError: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});

		pageLoad(1);
	});

	$(window).on('load', function(){
		$('#userName').css('width', $('#userName').parent().width() - 32);
		$('#userId').css('width', $('#userId').parent().width() - 114);
		$('#newPwd').css('width', $('#newPwd').parent().width() - 32);
		$('#chkPwd').css('width', $('#chkPwd').parent().width() - 32);
	});

	$(window).resize(function(){
		$('#userList').setGridWidth(0, true);
		$('#userList').setGridWidth($('.grid_box').width(), true);

		$('#userName').css('width', $('#userName').parent().width() - 32);
		$('#userId').css('width', $('#userId').parent().width() - 114);
		$('#newPwd').css('width', $('#newPwd').parent().width() - 32);
		$('#chkPwd').css('width', $('#chkPwd').parent().width() - 32);
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

	$("#userId").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^a-z0-9]/g, '');
		}
	});

	$("#newUser").click(function() {
		$("#userList").resetSelection();
		clearUserInfo();
		$("#userName").focus();
		$("#newflag").val("N");
	});

	$("#removeUser").click(function() {
		this.blur();

		var id = $("#userList").getGridParam("selrow");
		var row = $("#userList").getRowData(id);
		var ch = $("#challenge").val();

		if (row.id == "" || row.id == null) {
			alert(" ???????????? ???????????????.");
			return;
		}

		if (confirm(" " + row.name+" ["+row.id+"]  ?????????????????????????")) {
			$.ajax({
				type: "POST",
				url: "sub/removeUserInfo.jsp",
				data: {ch:ch, uid:row.id},
				dataType: "JSON",
				async: false,
				success: function(data) {
					var resultstatus = data.rows[0].resultstatus;
					if (resultstatus == 1) {
						$("#userList").delRowData(row.id);
						clearUserInfo();
						$("#newflag").val("N");
						//$("#userList").setGridParam({datatype:"local"}).trigger("reloadGrid");
						pageLoadAfterRemove(parseInt($("#curPage").val()));
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
						alert(" ID: " + row.id + " ?????? ?????? (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
					}
				},
				error: function(xhr, status, error) {
					ajaxerror(xhr, status, error);
				}
			});
		}
	});

	$("#setUser").click(function(){
		this.blur();
		var newflag = $("#newflag").val() == "N" ? "1" : "0";
		var name = XSSCheck($("#userName").val().trim());
		var uid = $("#userId").val().trim();
		var newpwd = $("#newPwd").val();
		var chkpwd = $("#chkPwd").val();
		var ch = $("#challenge").val();

		$("#userName").val(name);
		$("#userId").val(uid);

		if (name == null || name == "") {
			alert(" [??????]  ???????????????.");
			$("#userName").focus();
			return;
		}

		if (uid == null || uid == "") {
			alert(" [?????????]  ???????????????.");
			$("#userId").focus();
			return;
		}

		if (newflag == "1") {
			format = /^[A-Za-z0-9]{8,16}$/;
			if (!format.test(uid)) {
				alert(" ????????? ???????????? 8 ~ 16?????? ?????????, ????????? ???????????????.");
				$("#userId").focus();
				return;
			}

			var ind = $("#userList").getInd(uid);
			if (ind > 0) {
				alert(" ????????? ????????? ??????????????????.");
				$("#userId").focus();
				return;
			}

			if (uid != $("#checkid").val()) {
				alert(" ????????? [????????????] ?????????.");
				return;
			}

			if (newpwd == null || newpwd == "") {
				alert(" [????????????]  ???????????????.");
				$("#newPwd").focus();
				return;
			}

			format = /^(?=.*[a-zA-Z])(?=.*[!@#$%^*+=-])(?=.*[0-9]).{9,16}$/;
			if (!format.test(newpwd)) {
				alert(" [????????????]  ?????? ???????????? ???????????????.\n\n 9 ~ 16?????? ?????????, ??????, ????????????(!@#$%^*+=-)??? ??????");
				$("#newPwd").focus();
				return;
			}

			if (chkpwd == null || chkpwd == "") {
				alert(" [???????????? ??????]  ???????????????.");
				$("#chkPwd").focus();
				return;
			}

			if (newpwd != chkpwd) {
				alert(" [????????????]???  [???????????? ??????]??? ???????????? ????????????.");
				$("#chkPwd").focus();
				return;
			}
		}

		if (!confirm(" " + name+" ["+uid+"]  ?????????????????????????"))
			return;

		$.ajax({
			type: "POST",
			url: "sub/setUserInfo.jsp",
			data: {ch:ch, newflag:newflag, uid:uid, name:name, pwd:newpwd},
			dataType: "JSON",
			async: false,
			success: function(data) {
				var resultstatus = data.rows[0].resultstatus;
				if (resultstatus == 1) {
					if ($("#newflag").val() == "N") {
						$("#newflag").val("U");
						$("#newPwd").val("");
						$("#chkPwd").val("");
						$("#userId").prop("disabled", true);
						$("#newPwd").prop("disabled", true);
						$("#chkPwd").prop("disabled", true);
					}

					pageSearch("0", uid);
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
					alert(" ID: " + row.id + " ?????? ?????? (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
				}
			},
			error: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});
	});

	$("#searchName").keydown(function(e) {
		if (e.keyCode == 13) {
			if ($("#searchName").val().trim() != "") {
				pageSearch("1", $("#searchName").val().trim())
			}
		}
	});

	$("#userName").keydown(function(e) {
		if (e.keyCode == 13)
			$("#userId").focus();
	});
	$("#userId").keydown(function(e) {
		if (e.keyCode == 13) {
			if ($("#userId").val().trim() != "") {
				checkID();
			}
			else {
				$("#newPwd").focus();
			}
		}
	});
	$("#newPwd").keydown(function(e) {
		if (e.keyCode == 13)
			$("#chkPwd").focus();
	});

	function clearUserInfo()
	{
		$("#userName").val("");
		$("#userId").val("");
		$("#newPwd").val("");
		$("#chkPwd").val("");
		$("#userId").prop("disabled", false);
		$("#newPwd").prop("disabled", false);
		$("#chkPwd").prop("disabled", false);
		$("#searchName").val("");
	}

	function getUserInfo()
	{
		var id = $("#userList").getGridParam("selrow");

		$.ajax({
			type: "POST",
			url: "sub/getUserInfo.jsp",
			data: {uid: id},
			dataType: "json",
			async: false,
			success: function(data) {
				if (data != null && data.rows.length == 1) {
					var result = data.rows[0];

					clearUserInfo();
					$("#userName").val(result.name);
					$("#userId").val(result.id);
					$("#userId").prop("disabled", true);
					$("#newPwd").prop("disabled", true);
					$("#chkPwd").prop("disabled", true);

					$("#newflag").val("U");
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

	$("#checkUID").click(function() {
		checkID();
	});

	function checkID()
	{
		var id = $("#userId").val().trim();
		$("#userId").val(id);

		if (id == "" || id == null) {
			$("#userId").focus();
			return;
		}

		$.ajax({
			type: "POST",
			url: "sub/getUserInfo.jsp",
			data: {uid: id},
			dataType: "json",
			async: false,
			success: function(data) {
				if (data != null && data.rows.length == 1 && data.rows[0].id == id) {
					$("#checkid").val("");
					alert(" ????????? ??? ?????? ????????? ?????????.");
					$("#userId").focus();
				}
				else if (data.rows.length == 0) {
					$("#checkid").val(id);
					alert(" ?????? ????????? ????????? ?????????.");
				}
				else {
					alert(" ?????? ?????? ??????");
				}
			},
			error: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});
	}

	$("#first_pager").click(function() {
		if ($("#first_pager").hasClass('ui-state-disabled'))
			return;

		pageLoad(1);
	});

	$("#prev_pager").click(function() {
		if ($("#prev_pager").hasClass('ui-state-disabled'))
			return;

		var pageNo = parseInt($("#curPage").val()) - 1;
		pageLoad(pageNo);
	});

	$("#next_pager").click(function() {
		if ($("#next_pager").hasClass('ui-state-disabled'))
			return;

		var pageNo = parseInt($("#curPage").val()) + 1;
		pageLoad(pageNo);
	});

	$("#last_pager").click(function() {
		if ($("#last_pager").hasClass('ui-state-disabled'))
			return;

		var pageNo = parseInt($("#total_pager").text());
		pageLoad(pageNo);
	});

	$("#cur_pager").keydown(function(e) {
		var keyID = e.which ? e.which : e.keyCode;
		if (keyID == 16 || keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 16=shift 37=left 39=right 8=BS 46=Del
		}
		else if (!e.shiftKey && (keyID >= 48 && keyID <= 57)) {  // number
		}
		else if (keyID >= 96 && keyID <= 105) {  // extend number
		}
		else if (e.keyCode == 13 && $("#cur_pager").val() != "") {
			this.blur();
			var pageNo = parseInt($("#cur_pager").val());
			var curPage = parseInt($("#curPage").val());
			var lastPage = parseInt($("#total_pager").text());

			if (pageNo == 0) {
				pageNo = 1;
				$("#cur_pager").val(pageNo);
			}

			if (pageNo > lastPage) {
				pageNo = lastPage;
				$("#cur_pager").val(pageNo);
			}

			if (pageNo == curPage) {
				return;
			}

			pageLoad(pageNo);
		}
		else {
			return false;
		}
	});

	function setPageTag(totalCnt, curPage)
	{
		var maxRows = parseInt($("#pageRow").val());
		var pageCnt = parseInt((totalCnt - 1) / maxRows) + 1;

		if (curPage > pageCnt) {
			curPage = pageCnt;
		}

		$("#cur_pager").val(curPage);
		$("#total_pager").text(pageCnt);
		$("#total_count").text(totalCnt + " ???");

		$("#first_pager").removeClass('ui-state-disabled');
		$("#prev_pager").removeClass('ui-state-disabled');
		$("#next_pager").removeClass('ui-state-disabled');
		$("#last_pager").removeClass('ui-state-disabled');

		if (curPage == 1) {
			$("#first_pager").addClass('ui-state-disabled');
			$("#prev_pager").addClass('ui-state-disabled');
		}

		if (curPage == pageCnt) {
			$("#next_pager").addClass('ui-state-disabled');
			$("#last_pager").addClass('ui-state-disabled');
		}
	}

	function pageSearch(stype, svalue)
	{
		$("#userList").setGridParam({datatype:"json"});
		$("#userList").setGridParam({url:"sub/getUserListByVal.jsp", mtype:"POST", postData:{stype:stype, svalue:svalue, pagerow:$("#pageRow").val()}});
		$("#userList").trigger('reloadGrid');
	}

	function pageLoad(pageNo)
	{
		$("#curPage").val(pageNo);

		$("#userList").setGridParam({datatype:"json"});
		$("#userList").setGridParam({url:"sub/getUserList.jsp?pageno=" + pageNo + "&pagerow=" + $("#pageRow").val()});
		$("#userList").trigger('reloadGrid');
	}

	function pageLoadAfterRemove(pageNo)
	{
		var totalCnt = parseInt($("#total_count").text()) - 1;
		var maxRows = parseInt($("#pageRow").val());
		var pageCnt = parseInt((totalCnt - 1) / maxRows) + 1;

		if (pageNo > pageCnt) {
			pageNo = pageCnt;
		}

		$("#curPage").val(pageNo);

		$("#userList").setGridParam({datatype:"json"});
		$("#userList").setGridParam({url:"sub/getUserList.jsp?pageno=" + pageNo + "&pagerow=" + $("#pageRow").val()});
		$("#userList").trigger('reloadGrid');
	}

</script>
</body>
</html>
