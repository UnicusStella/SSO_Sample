<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.util.List"%>
<%@ page import="com.dreamsecurity.sso.lib.dss.s2.metadata.IDPSSODescriptor"%>
<%@ page import="com.dreamsecurity.sso.lib.dss.s2.metadata.SPSSODescriptor"%>
<%@ page import="com.dreamsecurity.sso.agent.config.*"%>
<%@ page import="com.dreamsecurity.sso.agent.metadata.MetadataRepository"%>
<%@ include file="../common.jsp"%>
<%
	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);
	SSOInit.initialize();

	MetadataRepository metaInstance = MetadataRepository.getInstance();
	IDPSSODescriptor idpDescriptor = metaInstance.getIDPDescriptor();
	List<String> spList = metaInstance.getSPNames();

	int idpServiceCount = idpDescriptor.getSingleSignOnServices().size();
	int spServiceCount = 0;
%>
<!DOCTYPE html>
<html>
<head>
	<title>Magic SSO Agent Metadata</title>
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
	<link rel="shortcut icon" href="../images/ds_tab.ico">
	<script src="../js/jquery-3.4.1.min.js" type="text/javascript"></script>

<style type="text/css">
#content { width:100%; min-width:1000px; }
#idpTable { width:100%; border:1px; }
#idpTable thead { text-align:center; background:#B3CDEE; }
#idpTable td { padding:.1em; border-right:1px solid #CCC; border-bottom:1px solid #CCC; }
#spTable { width:100%; border:1px; }
#spTable thead { text-align:center; background:#B3CDEE; }
#spTable td { padding:.1em; border-right:1px solid #CCC; border-bottom:1px solid #CCC; }
#subcontent { position:relative; width:100%; height:28px; margin-top:-10px; }
.version_text { display:inline-block; margin-top:6px; }
.btn_right_align { position:absolute; top:0px; right:2px; }
#headkey { width:200px; word-break:break-all; text-align:right; }
#headval { word-break:break-all; text-align:left; }
</style>
</head>
<body onload="">
	<div id="content">
	<h1 align="center">Magic SSO Agent Metadata : <%=SSOConfig.getInstance().getServerName()%></h1>
		<div id="subcontent">
			<span class="version_text">&nbsp;<%=SSOConfig.getElementVersion()%></span>
			<div class="btn_right_align">
<% if (idpServiceCount == 1) { %>
				<input type="checkbox" id="idpExcept"/>SP 정보만
				<input type="button" id="idpSave" value="IDP에 저장" style="width:100px;"/>
				&nbsp;&nbsp;&nbsp;&nbsp;
				<input type="button" id="spSave" value="SP에 저장" style="width:100px;"/>
<% } %>
			</div>
		</div>
		<table id="idpTable">
			<thead>
				<tr>
					<td id='headkey'>IDP Variable&nbsp;&nbsp;</td>
					<td id='headval'>&nbsp;Value</td>
				</tr>
			</thead>
			<tbody>
			<%
				out.println("<tr>");
				out.println("<td id='headkey'>entityID&nbsp;&nbsp;</td>");
				out.println("<td id='headval'>&nbsp;<input type='text' id=idpId style='width:500px; height:18px;' size='100' value='" +
						metaInstance.getIDPName() + "'/></td>");
				out.println("</tr>");

				if (idpServiceCount > 1) {
					for (int i = 0; i < idpServiceCount; i++) {
						out.println("<tr>");
						out.println("<td id='headkey'>RequestURL." +
								idpDescriptor.getSingleSignOnServices().get(i).getBinding() + "&nbsp;&nbsp;</td>");
						out.println("<td id='headval'>&nbsp;<input type='text' id=idpRequest style='width:500px; height:18px;' size='100' value='" +
								idpDescriptor.getSingleSignOnServices().get(i).getLocation() + "'/></td>");
						out.println("</tr>");
						out.println("<tr>");
						out.println("<td id='headkey'>LogoutURL." +
								idpDescriptor.getSingleLogoutServices().get(i).getBinding() + "&nbsp;&nbsp;</td>");
						out.println("<td id='headval'>&nbsp;<input type='text' id=idpLogout style='width:500px; height:18px;' size='100' value='" +
								idpDescriptor.getSingleLogoutServices().get(i).getLocation() + "'/></td>");
						out.println("</tr>");
					}
				}
				else {
					out.println("<tr>");
					out.println("<td id='headkey'>RequestURL&nbsp;&nbsp;</td>");
					out.println("<td id='headval'>&nbsp;<input type='text' id=idpRequest style='width:500px; height:18px;' size='100' value='" +
							idpDescriptor.getSingleSignOnServices().get(0).getLocation() + "'/></td>");
					out.println("</tr>");
					out.println("<tr>");
					out.println("<td id='headkey'>LogoutURL&nbsp;&nbsp;</td>");
					out.println("<td id='headval'>&nbsp;<input type='text' id=idpLogout style='width:500px; height:18px;' size='100' value='" +
							idpDescriptor.getSingleLogoutServices().get(0).getLocation() + "'/></td>");
					out.println("</tr>");
				}
			%>
			</tbody>
		</table>
		<br>
		<table id="spTable">
			<thead>
				<tr>
					<td id='headkey'>SP Variable&nbsp;&nbsp;</td>
					<td id='headval'>&nbsp;Value</td>
				</tr>
			</thead>
			<tbody>
			<%
				if (spList.size() > 0) {
					out.println("<tr>");
					out.println("<td id='headkey'>entityID&nbsp;&nbsp;</td>");
					out.println("<td id='headval'>&nbsp;<input type='text' id=spId style='width:500px; height:18px;' size='100' value='" +
							spList.get(0) + "'/></td>");
					out.println("</tr>");

					SPSSODescriptor spDescriptor = metaInstance.getSPDescriptor(spList.get(0));
					spServiceCount = spDescriptor.getAssertionConsumerServices().size();

					for (int i = 0; i < spServiceCount; i++) {
						out.println("<tr id=sprowb_" + i + " onmouseover='clickRow=this.rowIndex'>");
						out.println("<td id='headkey'>ResponseURL." + i + "&nbsp;&nbsp;</td>");
						out.println("<td id='headval'>&nbsp;<input type='text' id=spResponse_" + i + " style='width:500px; height:18px;' size='100' value='" +
								spDescriptor.getAssertionConsumerServices().get(i).getLocation() + "'/>");

						if (i != 0) {
				 			out.print("&nbsp;<input type='button' value='삭제' onClick='removeService();'></td>");
						}
				 		else {
				 			out.print("</td>");
				 		}

						out.println("</tr>");
						out.println("<tr id=sprowa_" + i + ">");
						out.println("<td id='headkey'>LogoutURL." + i + "&nbsp;&nbsp;</td>");
						out.println("<td id='headval'>&nbsp;<input type='text' id=spLogout_" + i + " style='width:500px; height:18px;' size='100' value='" +
								spDescriptor.getSingleLogoutServices().get(i).getLocation() + "'/></td>");
						out.println("</tr>");
					}
				}
			%>
			</tbody>
		</table>
		<br>
<% if (idpServiceCount == 1) { %>
		<input type="button" id="addService" value="URL 추가" style="width:100px; cursor:hand;"/>
		&nbsp;&nbsp;<input type="button" id="setHmac" value="검증파일 생성" style="cursor:hand;"/>
<% } %>
	</div>

<script type="text/javascript">
	var spCnt = <%=spServiceCount%>;
	var clickRow;

	$(document).ready(function(){
		$("#idpExcept").attr('checked', true);
	});

	$('#spSave').click(function() {
		this.blur();
		var idpid = $("#idpId").val();
		var idplogout = $("#idpLogout").val();
		var idprequest = $("#idpRequest").val();
		var spid = $("#spId").val();
		var splogout = "";
		var spresponse = "";

		for (var i = 0; i < spCnt; i++) {
			splogout += $("#spLogout_" + i).val() + "^";
			spresponse += $("#spResponse_" + i).val() + "^";
		}

		if (!confirm(" SP에 저장 하시겠습니까?")) {
			return;
		}

		$.ajax({
			type: "POST",
			url: "setMetaInfo.jsp",
			data: {idpid:idpid, idplogout:idplogout, idprequest:idprequest, spid:spid, splogout:splogout, spresponse:spresponse},
			dataType: "JSON",
			async: false,
			success: function(data) {
				var resultstatus = data.rows[0].resultstatus;
				if (resultstatus == 1) {
					alert(" SP에 저장 완료");
				}
				else {
					alert(" SP에 저장 오류 (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
				}
			},
			error: function(xhr, status, error) {
				alert(" SP에 저장 오류");
			}
		});
	});

	$('#idpSave').click(function() {
		this.blur();
		var url = "";
		var idpid = $("#idpId").val();
		var idplogout = $("#idpLogout").val();
		var idprequest = $("#idpRequest").val();
		var spid = $("#spId").val();
		var splogout = "";
		var spresponse = "";

		if ($('#idpExcept').is(":checked")) {
			idpid = "";
			idplogout = "";
			idprequest = "";
		}

		for (var i = 0; i < spCnt; i++) {
			splogout += $("#spLogout_" + i).val() + "^";
			spresponse += $("#spResponse_" + i).val() + "^";
		}

		var idx = $("#idpLogout").val().indexOf("/sso/");
		if (idx > 0) {
			url = $("#idpLogout").val().substring(0, idx + 5) + "/inc/setSPMetaInfo.jsp";
		}
		else {
			alert(" IDP URL 확인 바랍니다.");
			return;
		}

		if (!confirm(" IDP에 저장 하시겠습니까?")) {
			return;
		}

		$.ajax({
			type: "POST",
			url: url,
			data: {idpid:idpid, idplogout:idplogout, idprequest:idprequest, spid:spid, splogout:splogout, spresponse:spresponse},
			dataType: "jsonp",
			jsonpCallback: "setMeta",
			async: false,
			success: function(data) {
				var resultstatus = data.rows[0].resultstatus;
				if (resultstatus == 1) {
					alert(" IDP에 저장 완료");
				}
				else {
					alert(" IDP에 저장 오류 (" + resultstatus + ")\n\n " + data.rows[0].resultdata);
				}
			},
			error: function(xhr, status, error) {
				alert(" IDP에 저장 오류");
			}
		});
	});

	$('#addService').click(function() {
		var tagStr = "";
		tagStr += "<tr id=sprowb_" + spCnt + ">";
		tagStr += "<td id='headkey'>ResponseURL." + spCnt + "&nbsp;&nbsp;</td>";
		tagStr += "<td id='headval'>&nbsp;<input type='text' id=spResponse_" + spCnt + " style='width:500px; height:18px;' size='100'/></td>";
		tagStr += "</tr>";
		tagStr += "<tr id=sprowa_" + spCnt + " onmouseover='clickRow=this.rowIndex'>";
		tagStr += "<td id='headkey'>LogoutURL." + spCnt + "&nbsp;&nbsp;</td>";
		tagStr += "<td id='headval'>&nbsp;<input type='text' id=spLogout_" + spCnt + " style='width:500px; height:18px;' size='100'/>";
		tagStr += "&nbsp;&nbsp;<input type='button' value='삭제' onClick='removeService();'></td>";
		tagStr += "</tr>";
		spCnt++;

		$('#spTable > tbody:last').append(tagStr);
	});

	function removeService()
	{
		var index = parseInt((clickRow - 1) / 2) - 1;
		$('#sprowa_' + index).remove();
		$('#sprowb_' + index).remove();

		for (var i = (index + 1); i <= spCnt; i++) {
			$("#sprowa_" + i + " > td:first").html("LogoutURL." + (i - 1) + "&nbsp;&nbsp;");
			$("#sprowb_" + i + " > td:first").html("ResponseURL." + (i - 1) + "&nbsp;&nbsp;");
			$("#sprowa_" + i).attr("id", "sprowa_" + (i - 1));
			$("#sprowb_" + i).attr("id", "sprowb_" + (i - 1));
			$("#spLogout_" + i).attr("id", "spLogout_" + (i - 1));
			$("#spResponse_" + i).attr("id", "spResponse_" + (i - 1));
		}

		spCnt--;
	}

	$('#setHmac').click(function() {
		this.blur();

		if (!confirm(" 검증파일 생성 하시겠습니까?")) {
			return;
		}

		$.ajax({
			type: "POST",
			url: "setIntegrityFile.jsp",
			data: {},
			dataType: "JSON",
			async: false,
			success: function(data) {
				var resultstatus = data.rows[0].resultstatus;
				if (resultstatus == 1) {
					alert(" 검증파일 생성 완료");
				}
				else {
					alert(" 검증파일 생성 오류 (" + resultstatus + ")\n\n " + data.rows[0].resultdata);
				}
			},
			error: function(xhr, status, error) {
				alert(" 검증파일 생성 오류");
			}
		});
	});

</script>
</body>
</html>
