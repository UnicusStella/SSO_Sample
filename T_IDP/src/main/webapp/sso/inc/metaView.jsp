<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.util.List"%>
<%@ page import="com.dreamsecurity.sso.lib.dss.s2.metadata.IDPSSODescriptor"%>
<%@ page import="com.dreamsecurity.sso.lib.dss.s2.metadata.SPSSODescriptor"%>
<%@ page import="com.dreamsecurity.sso.server.config.SSOConfig"%>
<%@ page import="com.dreamsecurity.sso.server.metadata.MetadataRepository"%>
<%@ include file="../common.jsp"%>
<%
	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);

	MetadataRepository metaInstance = MetadataRepository.getInstance();
	IDPSSODescriptor idpDescriptor = metaInstance.getIDPDescriptor();
	List<String> spList = metaInstance.getSPNames();
%>
<!DOCTYPE html>
<html>
<head>
	<title>Magic SSO Server Metadata</title>
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
	<script src="../js/jquery-3.4.1.min.js" type="text/javascript"></script>

<style type="text/css">
#content { width:100%; min-width:1000px; }
#content table { width:100%; border:1px; }
#content table thead { text-align:center; background:#B3CDEE; }
#content table td { padding:.1em; border-right:1px solid #CCC; border-bottom:1px solid #CCC; }
#subcontent { position:relative; width:100%; height:28px; margin-top:-10px; }
.version_text { display:inline-block; margin-top:6px; }
#headkey { width:200px; word-break:break-all; text-align:right; }
#headval { word-break:break-all; text-align:left; }
</style>
</head>
<body onload="">
	<div id="content">
		<h1 align="center">Magic SSO Server Metadata : <%=SSOConfig.getInstance().getServerName()%></h1>
		<div id="subcontent">
			<span class="version_text">&nbsp;<%=SSOConfig.getElementVersion()%></span>
		</div>
		<table>
			<thead>
				<tr>
					<td id='headkey'>IDP Variable&nbsp;&nbsp;</td>
					<td id='headㅍ미'>&nbsp;Value</td>
				</tr>
			</thead>
			<tbody>
			<%
				out.println("<tr>");
				out.println("<td id='headkey'>entityID&nbsp;&nbsp;</td>");
				out.println("<td id='headval'>&nbsp;<input type='text' readonly id=idpId style='width:500px; height:18px;' size='100' value='" +
						metaInstance.getIDPName() + "'/></td>");
				out.println("</tr>");
				out.println("<tr>");
				out.println("<td id='headkey'>LogoutURL&nbsp;&nbsp;</td>");
				out.println("<td id='headval'>&nbsp;<input type='text' id=idpLogout style='width:500px; height:18px;' size='100' value='" +
						idpDescriptor.getSingleLogoutServices().get(0).getLocation() + "'/></td>");
				out.println("</tr>");
				out.println("<tr>");
				out.println("<td id='headkey'>RequestURL&nbsp;&nbsp;</td>");
				out.println("<td id='headval'>&nbsp;<input type='text' id=idpRequest style='width:500px; height:18px;' size='100' value='" +
						idpDescriptor.getSingleSignOnServices().get(0).getLocation() + "'/></td>");
				out.println("</tr>");
			%>
			</tbody>
		</table>
<%
	for (int j = 0; j < spList.size(); j++) {
%>
		<br id="br_<%=j%>">
		<table id="spTable_<%=j%>">
			<thead>
				<tr>
					<td id='headkey'>SP Variable&nbsp;&nbsp;</td>
					<td id='headval'>&nbsp;Value</td>
				</tr>
			</thead>
			<tbody>
			<%
				SPSSODescriptor spDescriptor = metaInstance.getSPDescriptor(spList.get(j));
				int spServiceCount = spDescriptor.getAssertionConsumerServices().size();

				out.println("<tr>");
				out.println("<td id='headkey'>entityID&nbsp;&nbsp;</td>");
				out.println("<td id='headval'>&nbsp;<input type='text' id='spId_" + j + "' style='width:500px; height:18px;' size='100' value='" + spList.get(j) + "'/>");
	 			out.print("&nbsp;<input type='button' value='저장' onClick='setSp(" + j + ");'>");
	 			out.print("&nbsp;&nbsp;<input type='button' value='URL 추가' onClick='addSpUrl(" + j + ");'>");
	 			out.print("&nbsp;&nbsp;<input type='button' value='삭제' onClick='removeSp(" + j + ");'>");
				out.print("<input type='hidden' id='spSvCnt_" + j + "' value='" + spServiceCount +"'/>");
				out.print("<input type='hidden' id='setFlag_" + j + "' value='1'/></td>");
				out.println("</tr>");

				for (int i = 0; i < spServiceCount; i++) {
					out.println("<tr id='sprowa_" + j + "_" + i + "'>");
					out.println("<td id='headkey'>LogoutURL." + i + "&nbsp;&nbsp;</td>");
					out.println("<td id='headval'>&nbsp;<input type='text' id='LogoutURL_" + j + "_" + i + "' style='width:500px; height:18px;' size='100' value='" +
							spDescriptor.getSingleLogoutServices().get(i).getLocation() + "'/></td>");
					out.println("</tr>");
					out.println("<tr id='sprowb_" + j + "_" + i + "'>");
					out.println("<td id='headkey'>ResponseURL." + i + "&nbsp;&nbsp;</td>");
					out.println("<td id='headval'>&nbsp;<input type='text' id='ResponseURL_" + j + "_" + i + "' style='width:500px; height:18px;' size='100' value='" +
							spDescriptor.getAssertionConsumerServices().get(i).getLocation() + "'/>");

					if (i != 0) {
			 			out.print("&nbsp;<input type='button' id='button_" + j + "_" + i + "' value='URL 삭제' onClick='removeSpUrl(" + j + ", " + i + ");'></td>");
					}
			 		else {
			 			out.print("</td>");
			 		}

					out.println("</tr>");
				}
			%>
			</tbody>
		</table>
<%
	}
%>
		<br id="insertSp">
		<input type="button" id="addSp" value="SP 추가" style="width:100px; cursor:hand;"/>
		&nbsp;&nbsp;<input type="button" id="setHmac" value="검증파일 생성" style="cursor:hand;"/>
	</div>

<script type="text/javascript">
	var spCnt = <%=spList.size()%>;

	$(document).ready(function(){
	});

	function setSp(index)
	{
		this.blur();

		var idpid = $("#idpId").val();
		var idplogout = $("#idpLogout").val();
		var idprequest = $("#idpRequest").val();

		var spid = $("#spId_" + index).val();
		var spsvcnt = parseInt($("#spSvCnt_" + index).val());
		var splogout = "";
		var spresponse = "";

		for (var i = 0; i < spsvcnt; i++) {
			splogout += $("#LogoutURL_" + index + "_" + i).val() + "^";
			spresponse += $("#ResponseURL_" + index + "_" + i).val() + "^";
		}

		if (idplogout == "") {
			alert(" 정보를 입력하세요.");
			$("#idpLogout").focus();
			return;
		}

		if (idprequest == "") {
			alert(" 정보를 입력하세요.");
			$("#idpRequest").focus();
			return;
		}

		if (spid == "") {
			alert(" 정보를 입력하세요.");
			$("#spId_" + index).focus();
			return;
		}

		if (splogout == "") {
			alert(" 정보를 입력하세요.");
			$("#LogoutURL_" + index + "_0").focus();
			return;
		}

		if (spresponse == "") {
			alert(" 정보를 입력하세요.");
			$("#ResponseURL_" + index + "_0").focus();
			return;
		}

		if (!confirm(" [ " + spid + " ]  저장 하시겠습니까?"))
			return;

		$.ajax({
			type: "POST",
			url: "setMetaInfo.jsp",
			data: {idpid:idpid, idplogout:idplogout, idprequest:idprequest, spid:spid, splogout:splogout, spresponse:spresponse},
			dataType: "JSON",
			async: false,
			success: function(data) {
				var resultstatus = data.rows[0].resultstatus;
				if (resultstatus == 1) {
					$("#setFlag_" + index).val('1');
					alert(" [ " + spid + " ] 저장 완료");
				}
				else {
					alert(" [ " + spid + " ] 저장 오류 (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
				}
			},
			error: function(xhr, status, error) {
				alert(" [ " + spid + " ] 저장 오류");
			}
		});
	}

	$('#addSp').click(function() {
		var tagStr = "";
		tagStr += "<br id='br_" + spCnt + "'>";
		tagStr += "<table id='spTable_" + spCnt + "'>";
		tagStr += "<thead><tr><td style='width:15%; text-align:right;'>SP Variable&nbsp;&nbsp;</td>";
		tagStr += "<td style='text-align:left;'>&nbsp;Value</td></tr></thead>";
		tagStr += "<tbody><tr><td id='headkey'>entityID&nbsp;&nbsp;</td>";
		tagStr += "<td id='headval'>&nbsp;<input type='text' id='spId_" + spCnt + "' style='width:500px; height:18px;' size='100'/>";
		tagStr += "&nbsp;&nbsp;<input type='button' value='저장' onClick='setSp(" + spCnt + ");'>";
		tagStr += "&nbsp;&nbsp;<input type='button' value='URL 추가' onClick='addSpUrl(" + spCnt + ");'>";
		tagStr += "&nbsp;&nbsp;<input type='button' value='삭제' onClick='removeSp(" + spCnt + ");'>";
		tagStr += "<input type='hidden' id='spSvCnt_" + spCnt + "' value='1'/><input type='hidden' id='setFlag_" + spCnt + "' value='0'/></td></tr>";
		tagStr += "<tr><td id='headkey'>LogoutURL.0&nbsp;&nbsp;</td>";
		tagStr += "<td id='headval'>&nbsp;<input type='text' id='LogoutURL_" + spCnt + "_0' style='width:500px; height:18px;' size='100'/></td></tr>";
		tagStr += "<tr><td id='headkey'>ResponseURL.0&nbsp;&nbsp;</td>";
		tagStr += "<td id='headval'>&nbsp;<input type='text' id='ResponseURL_" + spCnt + "_0' style='width:500px; height:18px;' size='100'/></td></tr>";
		tagStr += "</tbody></table>";
		spCnt++;

		$('#insertSp').before(tagStr);
	});

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
					alert(" 검증파일 생성 오류");
				}
			},
			error: function(xhr, status, error) {
				alert(" 검증파일 생성 오류");
			}
		});
	});

	function removeSp(index)
	{
		this.blur();

		var setflag = $("#setFlag_" + index).val();
		if (setflag == '0') {
			$('#br_' + index).remove();
			$('#spTable_' + index).remove();
			return;
		}

		var spid = $("#spId_" + index).val();
		if (spid == null || spid == "") {
			alert(" SP entityID 오류");
			return;
		}

		if (!confirm(" [ " + spid + " ]  삭제 하시겠습니까?"))
			return;

		$.ajax({
			type: "POST",
			url: "removeMetaInfo.jsp",
			data: {spid:spid},
			dataType: "JSON",
			async: false,
			success: function(data) {
				var resultstatus = data.rows[0].resultstatus;
				if (resultstatus == 1) {
					$('#br_' + index).remove();
					$('#spTable_' + index).remove();
					alert(" [ " + spid + " ] 삭제 완료");
				}
				else {
					alert(" [ " + spid + " ] 삭제 오류 (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
				}
			},
			error: function(xhr, status, error) {
				alert(" [ " + spid + " ] 삭제 오류");
			}
		});
	}

	function addSpUrl(index)
	{
		this.blur();
		var spsvcnt = parseInt($("#spSvCnt_" + index).val());

		var tagStr = "";
		tagStr += "<tr id='sprowa_" + index + "_" + spsvcnt + "'>";
		tagStr += "<td id='headkey'>LogoutURL." + spsvcnt + "&nbsp;&nbsp;</td>";
		tagStr += "<td id='headval'>&nbsp;<input type='text' id='LogoutURL_" + index + "_" + spsvcnt + "' style='width:500px; height:18px;' size='100'/>";
		tagStr += "</tr>";
		tagStr += "<tr id='sprowb_" + index + "_" + spsvcnt + "'>";
		tagStr += "<td id='headkey'>ResponseURL." + spsvcnt + "&nbsp;&nbsp;</td>";
		tagStr += "<td id='headval'>&nbsp;<input type='text' id='ResponseURL_" + index + "_" + spsvcnt + "' style='width:500px; height:18px;' size='100'/>";
		tagStr += "&nbsp;&nbsp;<input type='button' id='button_" + index + "_" + spsvcnt + "' value='URL 삭제' onClick='removeSpUrl(" + index + ", " + spsvcnt + ");'></td>";
		tagStr += "</tr>";

		$("#spTable_" + index + " > tbody:last").append(tagStr);
		$("#spSvCnt_" + index).val(spsvcnt + 1);
	}

	function removeSpUrl(index, svidx)
	{
		var spsvcnt = parseInt($("#spSvCnt_" + index).val());

		$('#sprowa_' + index + '_' + svidx).remove();
		$('#sprowb_' + index + '_' + svidx).remove();

		for (var i = (svidx + 1); i < spsvcnt; i++) {
			$("#sprowa_" + index + "_" + i + " > td:first").html("LogoutURL." + (i - 1) + "&nbsp;&nbsp;");
			$("#sprowb_" + index + "_" + i + " > td:first").html("ResponseURL." + (i - 1) + "&nbsp;&nbsp;");
			$("#sprowa_" + index + "_" + i).attr("id", "sprowa_" + index + "_" + (i - 1));
			$("#sprowb_" + index + "_" + i).attr("id", "sprowb_" + index + "_" + (i - 1));
			$("#LogoutURL_" + index + "_" + i).attr("id", "LogoutURL_" + index + "_" + (i - 1));
			$("#ResponseURL_" + index + "_" + i).attr("id", "ResponseURL_" + index + "_" + (i - 1));
			$("#button_" + index + "_" + i).attr("onClick", "removeSpUrl(" + index + ", " + (i - 1) + ");");
			$("#button_" + index + "_" + i).attr("id", "button_" + index + "_" + (i - 1));
		}

		$("#spSvCnt_" + index).val(spsvcnt - 1);
	}

</script>
</body>
</html>
