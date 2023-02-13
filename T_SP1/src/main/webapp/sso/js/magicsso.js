MagicSSO = new Object();

MagicSSO.actionUrl = "/sso/magicsso.jsp";

MagicSSO.isLogon = function()
{
	var resultStr = MagicSSO.request(MagicSSO.actionUrl, "tp=0", true)
	if (resultStr == null)
		result = "";

	if (resultStr == "true")
		result = true;
	else if (resultStr == "false")
		result = false;
	else
		result = false;

	return result;
};

MagicSSO.getID = function()
{
	var result = MagicSSO.request(MagicSSO.actionUrl, "tp=1&", true)
	if (result == null)
		result = "";

	return result;
};

MagicSSO.getToken = function()
{
	var result = MagicSSO.request(MagicSSO.actionUrl, "tp=2", true)
	if (result == null)
		result = "";

	return result;
};

MagicSSO.getProperty = function(id)
{
	var result = MagicSSO.request(MagicSSO.actionUrl, "tp=3&id=" + id, true)
	if (result == null)
		result = "";

	return result;
};

var xmlHttpRequest = null;
MagicSSO.request = function(url, param, sync, callbackFunction)
{
	if (xmlHttpRequest == null)
	{
		try {
			xmlHttpRequest = new XMLHttpRequest();
		}
		catch (e) {
			try {
				xmlHttpRequest = new ActiveXObject("Msxml2.HTTP");
			}
			catch (f) {
				xmlHttpRequest = new ActiveXObject("Microsoft.XMLHTTP");
			}
		}
	}

	xmlHttpRequest.open("POST", url, !sync);
	xmlHttpRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
	xmlHttpRequest.send(param);

	if (sync) {
		if(xmlHttpRequest.readyState == 4) {
			if(xmlHttpRequest.status == 200)
				return xmlHttpRequest.responseText;
			else 
				return null;
		}
		else {
			return null;
		}
	}
	else {
		xmlHttpRequest.onreadystatechange = function() {
			if (xmlHttpRequest.readyState == 4) {
				if (xmlHttpRequest.status == 200) {
					callbackFunction(xmlHttpRequest.responseText, 0);
				} else {
					callbackFunction(xmlHttpRequest.statusText, xmlHttpRequest.status);
				}
			}
		};
	}
};

function rltrim(str)
{
	return str.replace(/^\s+|\s+$/gm,'');
}
