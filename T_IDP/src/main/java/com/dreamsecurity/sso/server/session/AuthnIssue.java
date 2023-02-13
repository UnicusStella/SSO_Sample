package com.dreamsecurity.sso.server.session;

import java.io.Serializable;

import com.dreamsecurity.sso.lib.jtm.DateTime;

public class AuthnIssue implements Serializable
{
	private static final long serialVersionUID = 206103413294331425L;

	private String userId;
	private String providerName;
	private String deviceId;
	private String blockId;
	private String authnInfo;
	private DateTime issueTime;

	public AuthnIssue(String userId, String providerName, String deviceId, String blockId, String authnInfo, DateTime issueTime)
	{
		this.userId = userId;
		this.providerName = providerName;
		this.deviceId = deviceId;
		this.blockId = blockId;
		this.authnInfo = authnInfo;
		this.issueTime = issueTime;
	}

	public String getUserId()
	{
		return userId;
	}

	public void setUserId(String userId)
	{
		this.userId = userId;
	}

	public String getProviderName()
	{
		return providerName;
	}

	public void setProviderName(String providerName)
	{
		this.providerName = providerName;
	}

	public String getDeviceId()
	{
		return deviceId;
	}

	public void setDeviceId(String deviceId)
	{
		this.deviceId = deviceId;
	}

	public String getBlockId()
	{
		return blockId;
	}

	public void setBlockId(String blockId)
	{
		this.blockId = blockId;
	}

	public String getAuthnInfo()
	{
		return authnInfo;
	}

	public void setAuthnInfo(String authnInfo)
	{
		this.authnInfo = authnInfo;
	}

	public DateTime getIssueTime()
	{
		return issueTime;
	}

	public void setIssueTime(DateTime issueTime)
	{
		this.issueTime = issueTime;
	}

	public String toString()
	{
		StringBuffer sbInfo = new StringBuffer();

		sbInfo.append("userId=" + userId);
		sbInfo.append(" providerName=" + providerName);
		sbInfo.append(" deviceId=" + deviceId);
		sbInfo.append(" blockId=" + blockId);
		sbInfo.append(" authnInfo=" + authnInfo);
		sbInfo.append(" issueTime=" + issueTime);

		return sbInfo.toString();
	}
}