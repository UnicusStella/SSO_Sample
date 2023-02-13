<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ page session="true"%>
<%@ page import="com.dreamsecurity.sso.server.api.admin.AdminController"%>
<%@ page import="com.dreamsecurity.sso.server.util.OIDCUtil"%>
<%@ include file="adminCommon.jsp"%>
<%@ include file="sub/checkAdmin.jsp"%>
<%
	AdminController adminApi = new AdminController();
	String challenge = adminApi.createAdminCSRFToken(request);

	SSOConfig ssoconfig = SSOConfig.getInstance();
	String baseUrl = OIDCUtil.generateBaseUrl(request);
	String AUTH_ENDPOINT_PATH = baseUrl + ssoconfig.getString("oidc.endpoint.auth", "/oidc/auth");
	String TOKEN_ENDPOINT_PATH = baseUrl +ssoconfig.getString("oidc.endpoint.token", "/oidc/token");
	String LOGOUT_ENDPOINT_PATH = baseUrl +ssoconfig.getString("oidc.endpoint.logout", "/oidc/logout");
	String INTROSPECT_ENDPOINT_PATH = baseUrl +ssoconfig.getString("oidc.endpoint.introspect", "/oidc/introspect");
	String USERINFO_ENDPOINT_PATH =  baseUrl + ssoconfig.getString("oidc.endpoint.userinfo", "/oidc/userinfo");
	String ISSUER =  baseUrl;
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
</head>
<body>
	<div class="page-holder">
		<input type="hidden" id="adminid" value="<%=XSSCheck(adminid)%>"/>
		<input type="hidden" id="adminip" value="<%=XSSCheck(adminip)%>"/>
		<input type="hidden" id="currip" value="<%=XSSCheck(currip)%>"/>
		<input type="hidden" id="challenge" value="<%=XSSCheck(challenge)%>"/>
		<input type="hidden" id="newflag" value="U">
		<input type="hidden" id="getInfoflag" value=-1>

		<div class="page-breadcrumb">
			HOME / 클라이언트 / 클라이언트 관리
		</div>
		<div class="page-header">
			<h4 class="title">클라이언트 관리</h4>
		</div>

		<div class="d-flex">
			<div class="content-box width-40p mr-10">
				<div class="content-top">
					<div class="float-left">
						<button class="subtitle-btn" type="button"></button>
						<span class="subtitle-text">클라이언트 리스트</span>
					</div>
					<div class="float-right">
						<button class="btn" type="button" id="removeClient">삭 제</button>
					</div>
				</div>
				<div class="content-body pb-15" id="clientlist-box">
					<table id="clientList"></table>
				</div>
			</div>

			<div class="content-box width-60p ml-10">
				<div class="content-top">
					<div class="float-left">
						<button class="subtitle-btn" type="button"></button>
						<span class="subtitle-text">클라이언트 정보</span>
					</div>
					<div class="float-right">
						<button class="btn" type="button" id="newClient">신 규</button>
						<button class="btn ml-5" type="button" id="setClient">저 장</button>
						<button class="btn ml-5" type="button" id="downConfig">설정 다운</button>
					</div>
				</div>
				<div class="content-body pb-15">
					<div class="div-block height-550 line-top line-bottom overflow_auto">
						<div class="div-block mt-15 ml-15 overflow_auto">
							<div class="float-left width-22p pt-5" title="Unique Service Provider Name">
								<label class="font-wt-600" for="cname">이름</label>
							</div>
							<div class="float-left width-78p">
								<input class="basic_input width-85p height-30" type="text" id="cname">
							</div>
						</div>
						<div class="div-block mt-10 ml-15 overflow_auto">
							<div class="float-left width-22p pt-5" title="Unique Service Provider ID">
								<label class="font-wt-600" for="cid">아이디</label>
							</div>
							<div class="float-left width-78p">
								<input class="basic_input width-85p height-30" type="text" id="cid">
							</div>
						</div>
						<div class="div-block mt-10 ml-15 overflow_auto">
							<div class="float-left width-22p pt-5" title="인증 프로토콜">
								<label class="font-wt-600" for="protocol">인증 프로토콜</label>
							</div>
							<div class="float-left width-50p">
								<select class="search-base width-80" id="protocol" onchange="changeProtocol(this);">
									<option value="OIDC" selected>OIDC</option>
								</select>
							</div>
						</div>
						<div class="div-block mt-10 ml-15 overflow_auto">
							<div class="float-left width-22p pt-5" title="클라이언트 사용 여부">
								<label class="font-wt-600" for="enabled">사용 여부</label>
							</div>
							<div class="float-left width-50p">
								<input type="checkbox" id="enabled" checked class="input__on-off">
								<label for="enabled" class="label__on-off">
									<span class="marble"></span>
									<span class="on">on</span>
									<span class="off">off</span>
								</label>
							</div>
						</div>
						<div class="div-block mt-10 ml-15 overflow_auto">
							<div class="float-left width-22p pt-5" title="인증 완료 후 리다이렉트 되는 URI">
								<label class="font-wt-600" for="redirectUri">리다이렉트 URIs</label>
							</div>
							<div class="float-left width-78p">
								<div id="redirectDiv">
									<div class="width-100p">
										<input class="basic_input width-85p height-30" type="text" id="redirectUri">
										<button class="btn_client width-40 height-30 ml-5" type="button" onclick="addUri(this)">+</button>
									</div>
								</div>
							</div>
						</div>
						<div id="oidcDiv">
							<div class="div-block mt-10 ml-15 overflow_auto">
								<div class="float-left width-22p pt-5" title="인증 서버와 통신 시 사용하는 키">
									<label class="font-wt-600" for="secret">Secret 키</label>
								</div>
								<div class="float-left width-78p">
									<input class="basic_input width-85p height-30" type="text" id="secret" disabled>
								</div>
							</div>
							<div class="div-block mt-10 ml-15 overflow_auto">
								<div class="float-left width-22p pt-5" title="토큰 검증 시 보안 기능 추가">
									<label class="font-wt-600" for="nonce">Nonce 보안</label>
								</div>
								<div class="float-left width-50p">
									<input type="checkbox" id="nonce" checked class="input__on-off">
									<label for="nonce" class="label__on-off">
										<span class="marble"></span>
										<span class="on">on</span>
										<span class="off">off</span>
									</label>
								</div>
							</div>
							<div class="div-block mt-10 ml-15 overflow_auto">
								<div class="float-left width-22p pt-5" title="Auth Code 검증 시 보안 기능 추가">
									<label class="font-wt-600" for="pkce">PKCE 보안</label>
								</div>
								<div class="float-left width-50p">
									<input type="checkbox" id="pkce" class="input__on-off">
									<label for="pkce" class="label__on-off">
										<span class="marble"></span>
										<span class="on">on</span>
										<span class="off">off</span>
									</label>
								</div>
							</div>
							<div class="div-block mt-10 ml-15 overflow_auto">
								<div class="float-left width-22p pt-5" title="Refresh 토큰 발행 여부">
									<label class="font-wt-600" for="refresh">Refresh 토큰 발행</label>
								</div>
								<div class="float-left width-50p">
									<input type="checkbox" id="refresh" checked class="input__on-off">
									<label for="refresh" class="label__on-off">
										<span class="marble"></span>
										<span class="on">on</span>
										<span class="off">off</span>
									</label>
								</div>
							</div>
							<div class="div-block mt-10 ml-15 overflow_auto">
								<div class="float-left width-22p pt-5" title="Auth Code 만료 시간">
									<label class="font-wt-600" for="codeLife">Auth Code 만료</label>
								</div>
								<div class="width-78p height-30">
									<input class="right_input height-30" id="codeLife" type="number" min=0 max=100 value=10>
									<select class="search-base width-60 height-30 ml-5" id="codeLifeSelect">
										<option value="sec" selected>초</option>
									</select>
								</div>
							</div>
							<div class="div-block mt-10 ml-15 overflow_auto">
								<div class="float-left width-22p pt-5" title="ID 토큰, Access 토큰 만료 시간">
									<label class="font-wt-600" for="tokenLife">ID/Access 토큰 만료</label>
								</div>
								<div class="width-78p height-30">
									<input class="right_input height-30" id="tokenLife" type="number" min=0 max=100 value=10>
									<select class="search-base width-60 height-30 ml-5" id="tokenLifeSelect">
										<option value="min" selected>분</option>
										<option value="hour">시간</option>					
									</select>
								</div>
							</div>
							<div class="div-block mt-10 ml-15 overflow_auto">
								<div class="float-left width-22p pt-5" title="Refresh 토큰 만료 시간">
									<label class="font-wt-600" for="refreshLife">Refresh 토큰 만료</label>
								</div>
								<div class="width-78p height-30">
									<input class="right_input height-30" id="refreshLife" type="number" min=0 max=100 value=30>
									<select class="search-base width-60 height-30 ml-5" id="refreshLifeSelect">
										<option value="min" selected>분</option>
										<option value="hour">시간</option>					
									</select>
								</div>
							</div>
							<div class="div-block mt-10 ml-15 overflow_auto">
								<div class="float-left width-22p pt-5" title="인증서버에서 허용할 클라이언트 요청(범위)">
									<label class="font-wt-600" for="">Scope</label>
								</div>
								<div class="float-left width-78p mb-15">
									<div class="float-left width-28p mr-15">
										<select class="width-100p height-100 overflow_auto text-center" multiple size="5" id="availableScope">
										</select>
									</div>
									<div class="float-left width-20p mr-15">
										<button class="btn_normal width-100p height-30 mt-10" type="button" id="addScope"><span>추가 &gt;&gt;</span></button>
										<button class="btn_normal width-100p height-30 mt-10" type="button" id="removeScope">&lt;&lt; 제외</button>
									</div>
									<div class=" float-left width-28p">
										<select class="width-100p height-100 overflow_auto text-center" multiple size="5" id="currentScope">				
										</select>									
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>
	</div>

<script type="text/javascript">

	var redirectUriId = "redirectUri";
	var redirectDivId = "redirectDiv";
	var redirectBtnId = "redirectBtn";
	var countBox = 0;

	var publicKey = "";

	$(document).ready(function(){
		checkAdmin();
		clearClientInfo();
		getScopeList();
		$("#newflag").val("N");
		$("#clientList").jqGrid({
			url: "sub/getClientList.jsp",
			datatype: "json",
			colNames: ['이름', '아이디', '프로토콜'],
		    colModel: [
		          {name:'name', index:'name', width:'40%', align:'center', sortable:false},
		  	      {name:'id', index:'id', width:'40%', align:'center', sortable:false},
		  	      {name:'protocol', index:'protocol', width:'20%', align:'center', sortable:false}
			],
			id: 'id',
		    rowNum: 1000000,
		    rownumbers: true,
		    gridview: true,
			scrollrows: true,
			loadonce: true,
			sortable: true,
			sortname: 'name',
		    height: 521,
		    loadtext: 'Loading...',
			onSelectRow: function() {
				if ($("#getInfoflag").val() == -1)
					getClientInfo();
				else
					$("#getInfoflag").val(-1);
			},
		    loadComplete:function(){
				$('#clientList').setGridWidth($('#clientlist-box').width(), true);

				var code = $("#cid").val();
				if (code != "" && code != null) {
					if ($("#clientList").getInd(code) != false) {
						$("#getInfoflag").val(9);
						$("#clientList").setSelection(code);
					}
				}
		    },
			loadError: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		}).setGridWidth($('#clientlist-box').width(), true);
	});

	$(window).ready(function() {
	});

	$(window).resize(function() {
		$('#clientList').setGridWidth($('#clientlist-box').width(), true);
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

	function changeProtocol(obj)
	{
		obj.blur();

		var selectValue = obj.options[obj.selectedIndex].value;
		var oidcDiv = document.getElementById("oidcDiv");

		if (selectValue == "OIDC") {
			oidcDiv.style.display = "block";
		}
		else {
			oidcDiv.style.display = "none";
		}
	}

	function addUri()
	{
		var newUriId = redirectUriId + countBox;
		var newDivId = redirectDivId + countBox;
		var newBtnId = redirectBtnId + countBox;

		var redirectUri = document.getElementById(redirectUriId).value;

		if (redirectUri == "" || redirectUri == null) {
			alert(" [리다이렉트 URIs]  입력하세요.");
			return;
		}

		document.getElementById('redirectDiv').innerHTML += '<div class="width-100p" id="' + newDivId + '">';	
		document.getElementById('redirectDiv').innerHTML += '<input class="basic_input width-85p height-30" type="text" id="' + newUriId + '" value="' + redirectUri + '">';
		document.getElementById('redirectDiv').innerHTML += '\n<button for="' + countBox + '" class="btn_client width-40 height-30 ml-5" type="button" id="' + newBtnId + '" onclick="removeUri(this);">-</button>';
		document.getElementById('redirectDiv').innerHTML += '</div>';
		countBox++;
	}

	function removeUri(obj)
	{
		var removeObjId = obj.getAttribute('for');
		var removeUri = document.getElementById(redirectUriId + removeObjId);
		var removeDiv = document.getElementById(redirectDivId + removeObjId);
		var removeParent = obj.parentElement;

		removeParent.removeChild(obj);
		removeParent.removeChild(removeUri);
		removeParent.removeChild(removeDiv);
	}

	$('#addScope').click(function() {
		var selectedValues = [];
		var selectedTexts = [];		

	    $("#availableScope :selected").each(function(){
	        selectedTexts.push($(this).text());
	        selectedValues.push($(this).val());
	    });

	    if (selectedValues.length < 1) {
			alert(" [Scope]  선택하세요.");
			return;
	    }

	    for (var i = 0; i < selectedValues.length; i++) {
	    	var selectValue = selectedValues[i];
	    	var selectText = selectedTexts[i];
	    	$("#currentScope").append("<option value="+selectValue+">"+selectText+"</option>");
		    $('#availableScope option[value=' + selectValue + ']').remove();
	    }
	});
	
	$('#removeScope').click(function() {
		var selectedValues = [];
		var selectedTexts = [];

		$("#currentScope :selected").each(function(){
	        selectedTexts.push($(this).text());
	        selectedValues.push($(this).val());
		});

		if (selectedValues.length < 1) {
			alert(" [Scope]  선택하세요.");
			return;
		}

		for (var i = 0; i < selectedValues.length; i++) {
	    	var selectValue = selectedValues[i];
	    	var selectText = selectedTexts[i];

	    	if (selectText != "openid") {
		   		$("#availableScope").append("<option value=" + selectValue + ">" + selectText + "</option>");
		   		$('#currentScope option[value=' + selectValue + ']').remove();
	    	}
	    	else {
	    		$('#currentScope option[value=' + selectValue + ']').prop("selected", false);
	    	}
		}
	});

	function clearClientInfo()
	{
		$("#cid").val("");
		$("#cname").val("");
		$("input:checkbox[id='enabled']").prop("checked", true);
		$("#redirectUri").val("");
		$("#secret").val("");
		$("input:checkbox[id='nonce']").prop("checked", true);
		$("input:checkbox[id='pkce']").prop("checked", false);
		$("input:checkbox[id='refresh']").prop("checked", true);
		$("#codeLife").val("10");
		$("#tokenLife").val("10");
		$('#tokenLifeSelect').val('min').prop("selected",true);
		$("#refreshLife").val("30");
		$('#refreshLifeSelect').val('min').prop("selected",true);
		$('#availableScope').children('option').remove();
		$('#currentScope').children('option').remove();

		for (var i = 0; i < countBox; i++) {
			var removeBtn = document.getElementById(redirectBtnId + i);

			if (removeBtn != null)
				removeUri(removeBtn);
		}

		countBox = 0;
	}

	function getScopeList()
	{
		$.ajax({
			type: "POST",
			url: "sub/getScopeList.jsp",
			data: {},
			dataType: "json",
			async: false,
			success: function(data) {
				if (data != null && data.rows.length > 0) {
					for (var i = 0; i < data.rows.length; i++) {
						var result = data.rows[i];

						if (result.id == "openid")
							$('#currentScope').append("<option value='" + result.id + "'>" + result.id + "</option>");
						else
							$('#availableScope').append("<option value='" + result.id + "'>" + result.id + "</option>");
					}
				}
				else {
					alert(" Scope 조회 오류");
				}
			},
			error: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});	
	}

	$("#newClient").click(function() {
		$("#clientList").resetSelection();

		clearClientInfo();
		getScopeList();
		$("#newflag").val("N");
		$("#cid").prop("disabled", false);

		$("#cname").focus();
	});

	function getClientInfo()
	{
		clearClientInfo();

		var cid = $("#clientList").getGridParam("selrow");

		$.ajax({
			type: "POST",
			url: "sub/getClientInfo.jsp",
			data: {id:cid},
			dataType: "json",
			async: false,
			success: function(data) {
				if (data != null && data.rows.length == 1) {
					var result = data.rows[0];

					$("#cname").val(result.name);
					$("#cid").val(result.id);
					$('#protocol').val(result.protocol).prop("selected", true);

					if (result.enabled == "1")
						$("input:checkbox[id='enabled']").prop("checked", true);
					else
						$("input:checkbox[id='enabled']").prop("checked", false);

					if (result.protocol == "OIDC") {
						oidcDiv.style.display = "block";

						$("#secret").val(result.secret);

						if (result.nonce == "1")
							$("input:checkbox[id='nonce']").prop("checked", true);
						else
							$("input:checkbox[id='nonce']").prop("checked", false);

						if (result.pkce == "1")
							$("input:checkbox[id='pkce']").prop("checked", true);
						else
							$("input:checkbox[id='pkce']").prop("checked", false);

						if (result.refreshTokenUse == "1")
							$("input:checkbox[id='refresh']").prop("checked", true);
						else
							$("input:checkbox[id='refresh']").prop("checked", false);

						$("#codeLife").val(result.codeLifespan);

						if (result.tokenLifespan % 3600 == 0) {
							$("#tokenLife").val(result.tokenLifespan/3600);
							$('#tokenLifeSelect').val('hour').prop("selected", true);
						}
						else if (result.tokenLifespan % 60 == 0) {
							$("#tokenLife").val(result.tokenLifespan/60);
							$('#tokenLifeSelect').val('min').prop("selected", true);
						}
						else {
						}

						if (result.refreshTokenLifespan % 3600 == 0) {
							$("#refreshLife").val(result.refreshTokenLifespan/3600);
							$('#refreshLifeSelect').val('hour').prop("selected", true);
							
						}
						else if (result.refreshTokenLifespan % 60 == 0) {
							$("#refreshLife").val(result.refreshTokenLifespan/60);
							$('#refreshLifeSelect').val('min').prop("selected", true);
						}
						else {
						}

						publicKey = result.serverCert;
					}
					else {
						oidcDiv.style.display = "none";
					}

					$("#newflag").val("U");
					$("#cid").prop("disabled", true);

					getClientRedirectUri(cid);
					getClientScope(cid);
				}
				else {
					alert(" 조회 오류");
				}
			},
			error: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});
	}

	function getClientRedirectUri(clientId)
	{
		$.ajax({
			type: "POST",
			url: "sub/getClientRedirect.jsp",
			data: {id:clientId},
			dataType: "json",
			async: false,
			success: function(data) {
				if (data != null && data.rows.length > 0) {
					for (var i = 0; i < data.rows.length; i++) {
						var result = data.rows[i];
						$("#redirectUri").val(decodeURIComponent(result.redirectUri));
						addUri();
					}
				}
				else {
				}
			},
			error: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});
	}

	function getClientScope(clientId)
	{
		$.ajax({
			type: "POST",
			url: "sub/getClientScope.jsp",
			data: {id:clientId},
			dataType: "json",
			async: false,
			success: function(data) {
				if (data != null && data.rows.length > 0) {
					for (var i = 0; i < data.rows.length; i++) {
						var result = data.rows[i];
						if (result.enabled == "1" || result.scope == "openid")
							$('#currentScope').append("<option value='"+result.scope+"'>"+result.scope+"</option>");
						else
							$('#availableScope').append("<option value='"+result.scope+"'>"+result.scope+"</option>");
					}
				}
				else {
					alert(" 조회 오류");
				}
			},
			error: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});
	}

	$("#setClient").click(function() {
		this.blur();
		var newflag = $("#newflag").val() == "N" ? "1" : "0";
		var ch = $("#challenge").val();

		var cname = XSSCheck($("#cname").val().trim());
		$("#cname").val(cname);

		var cid = XSSCheck($("#cid").val().trim().toUpperCase());
		$("#cid").val(cid);

		var protocol = $("#protocol :selected").val();
		var enabled = $('#enabled').is(':checked') == true ? "1" : "0";

		var responseType = "code";
		var grantType = "authorization_code";

		var redirectUriList = [];
		for (var i=0; i<countBox; i++) {
			var redirectUri = document.getElementById(redirectUriId + i);

			if (redirectUri != null)
				redirectUriList.push(encodeURIComponent(redirectUri.value));
		}

		var secret = $('#secret').val();
		var nonce = $('#nonce').is(':checked') == true ? "1" : "0";
		var pkce = $('#pkce').is(':checked') == true ? "1" : "0";
		var refresh = $('#refresh').is(':checked') == true ? "1" : "0";
		var codeLife = $("#codeLife").val().trim();

		var tokenLife = $("#tokenLife").val().trim();
		var tokenLifeType = $("#tokenLifeSelect :selected").val();
		tokenLife = tokenLifeType == "min" ? tokenLife * 60 : tokenLife * 3600;

		var refreshLife = $("#refreshLife").val().trim();
		var refreshLifeType = $("#refreshLifeSelect :selected").val();
		refreshLife = refreshLifeType == "min" ? refreshLife * 60 : refreshLife * 3600;

		var scopeList = [];
		$("#currentScope option").each(function(){
			scopeList.push($(this).val());
		});

		if (cname == null || cname == "") {
			alert(" [클라이언트 이름]  입력하세요.");
			$("#cname").focus();
			return;
		}

		if (cid == null || cid == "") {
			alert(" [클라이언트 아이디]  입력하세요.");
			$("#cid").focus();
			return;
		}

		if ($("#newflag").val() == "N") {
			var clientIdList = $("#clientList").jqGrid("getCol", "id", true);
			for (var i = 0; i < clientIdList.length; i++) {
				if (clientIdList[i].value == cid) {
					alert(" 이미 등록된 클라이언트 아이디입니다.");
					$("#cid").focus();
					return;
				}
			}
		}

		if (redirectUriList.length < 1) {
			alert(" [리다이렉트 URIs]  추가하세요.");
			$("#redirectUri").focus();
			return;
		}

		var removeDupCount = new Set(redirectUriList);
		if (removeDupCount.size != redirectUriList.length) {
			alert(" [리다이렉트 URIs] 중복 확인하세요.");
			$("#redirectUri").focus();
			return;
		}

		var seturl = "";
		var setdata = {};

		if (protocol == "OIDC") {
			if (codeLife == null || codeLife == "") {
				alert(" [Auth Code 만료]  입력하세요.");
				$("#codeLife").focus();
				return;
			}

			if (tokenLife == null || tokenLife == "") {
				alert(" [ID/Access 토큰 만료]  입력하세요.");
				$("#tokenLife").focus();
				return;
			}

			if (refreshLife == null || refreshLife == "") {
				alert(" [Refresh 토큰 만료]  입력하세요.");
				$("#refreshLife").focus();
				return;
			}

			var currentScopeNum = $('#currentScope option').length;

			if (currentScopeNum < 1) {
				alert(" [Scope]  선택하세요.");
				$("#availableScope").focus();
				return;
			}
		}

		if (!confirm(" [" + cname + "]  저장하시겠습니까?")) {
			return;
		}

		if (protocol == "SAML") {
			$('#secret').val("");
			secret = "";
		}

		$.ajax({
			type: "POST",
			url: "sub/setClient.jsp",
			data: {ch:ch, newflag:newflag, id:cid, name:cname, protocol:protocol, enabled:enabled, redirectUriList:redirectUriList,
					responseType:responseType, grantType:grantType, secret:secret, nonce:nonce, pkce:pkce, refresh:refresh, codeLife:codeLife,
					tokenLife:tokenLife, refreshLife:refreshLife, scopeList:scopeList},
			dataType: "JSON",
			traditional: true,
			async: false,
			success: function(data) {
				var resultstatus = data.rows[0].resultstatus;

				if (resultstatus == 1) {
					if (data.rows[0].resultdata != "")
						$("#secret").val(data.rows[0].resultdata);

					if ($("#newflag").val() == "N") {
						$("#newflag").val("U");
						$("#cid").prop("disabled", true);

						var newRowData = {'name':cname, 'id':cid, 'protocol':protocol};
	      				$("#clientList").addRowData(cid, newRowData, "last");
	      				$("#clientList").setGridParam({datatype:"local"}).trigger("reloadGrid");
					}
					else {
						$("#clientList").setCell(cid, 'name', cname);
						$("#clientList").setCell(cid, 'protocol', protocol);
					}

					alert(" 저장 완료");
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
					alert(" ID: " + row.id + " 저장 오류 (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
				}
			},
			error: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});
	});

	$("#removeClient").click(function() {
		this.blur();
		var ch = $("#challenge").val();
		var id = $("#clientList").getGridParam("selrow");
		var row = $("#clientList").getRowData(id);

		if (row.id == "" || row.id == null) {
			alert(" 클라이언트를 선택하세요.");
			return;
		}

		if (confirm(" [" + row.name + "]  삭제하시겠습니까?")) {
			$.ajax({
				type: "POST",
				url: "sub/removeClient.jsp",
				data: {ch:ch, id:row.id},
				dataType: "JSON",
				async: false,
				success: function(data) {
					var resultstatus = data.rows[0].resultstatus;

					if (resultstatus == 1) {
						clearClientInfo();
						getScopeList();
						$("#newflag").val("N");
						$("#cid").prop("disabled", false);

						$("#clientList").delRowData(row.id);
						$("#clientList").setGridParam({datatype:"local"}).trigger("reloadGrid");
						alert(" 삭제 완료");
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
						alert(" ID: " + row.id + " 삭제 오류 (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
					}
				},
				error: function(xhr, status, error) {
					ajaxerror(xhr, status, error);
				}
			});
		}
	});

 	$('#downConfig').click(function() {
 		this.blur();
		var id = $("#clientList").getGridParam("selrow");
		var row = $("#clientList").getRowData(id);

		if (row.id == null || row.id == "") {
			alert(" [클라이언트]  선택하세요.");
			return;
		}

		if (row.protocol != "OIDC") {
			alert(" OIDC 인증 프로토콜만 가능합니다.");
			return;
		}

		getClientInfo();

		var clientId = $("#cid").val();
		var protocol = $("#protocol :selected").val();
		var secret = $("#secret").val();
		var responseType = "code";
		var grantType = "authorization_code";
		var nonceEnabled = $('#nonce').is(':checked') == true ? "1" : "0";
		var pkceEnabled = $('#pkce').is(':checked') == true ? "1" : "0";
		var refreshTokenEnabled = $('#refresh').is(':checked') == true ? "1" : "0";
		var scopeList = [];
		var redirectUriList = [];
		var authEndpointPath = "<%=AUTH_ENDPOINT_PATH%>";
		var tokenEndpointPath = "<%=TOKEN_ENDPOINT_PATH%>";
		var logoutEndpointPath = "<%=LOGOUT_ENDPOINT_PATH%>";
		var introspectEndpointPath = "<%=INTROSPECT_ENDPOINT_PATH%>";
		var userinfoEndpointPath = "<%=USERINFO_ENDPOINT_PATH%>";
		var issuer = "<%=ISSUER%>";

		$("#currentScope option").each(function(){
			scopeList.push($(this).text());
		});

		for (var i = 0; i < countBox; i++) {
			redirectUri = document.getElementById(redirectUriId + i);

			if (redirectUri != null)
				redirectUriList.push(redirectUri.value);
		}

		var data = {
				clientId: clientId,
				protocol: protocol,
				secret: secret,
				responseType: responseType,
				grantType: grantType,
				nonceEnabled: nonceEnabled,
				pkceEnabled: pkceEnabled,
				refreshTokenEnabled: refreshTokenEnabled,
				scopes: scopeList,
				redirectUris: redirectUriList,
				authEndpoint: authEndpointPath,
				tokenEndpoint: tokenEndpointPath,
				logoutEndpoint: logoutEndpointPath,
				introspectEndpoint: introspectEndpointPath,
				userinfoEndpoint: userinfoEndpointPath,
				issuer: issuer,
				publicKey: publicKey
		}

		var jsonData = JSON.stringify(data);
		var contentType = 'text/plain';
		var downloadObj = document.createElement("a");
		var file = new Blob([jsonData], {type: contentType});
		downloadObj.href = URL.createObjectURL(file);
		downloadObj.download = 'oidc-' + clientId + '.json';
		downloadObj.click();
	});

	$("#cname").keydown(function(e) {
		if (e.keyCode == 13)
			if ($("#newflag").val() == "N")
				$("#cid").focus();
			else
				$("#redirectUri").focus();
	});
	$("#cid").keydown(function(e) {
		if (e.keyCode == 13)
			$("#redirectUri").focus();
	});
	$("#codeLife").keydown(function(e) {
		if (e.keyCode == 13)
			$("#tokenLife").focus();
	});
	$("#tokenLife").keydown(function(e) {
		if (e.keyCode == 13)
			$("#refreshLife").focus();
	});

	$("#cid").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^A-Za-z0-9_]/g, '');
		}
	});
	$("#codeLife").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^0-9]/g, '');
		}
	});
	$("#tokenLife").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^0-9]/g, '');
		}
	});
	$("#refreshLife").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^0-9]/g, '');
		}
	});

</script>
</body>
</html>