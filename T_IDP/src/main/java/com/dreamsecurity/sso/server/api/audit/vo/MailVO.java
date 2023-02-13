package com.dreamsecurity.sso.server.api.audit.vo;

public class MailVO
{
	private String smtpHost;
	private String smtpPort;
	private String smtpChnl;
	private String smtpAuth;
	private String authName;
	private String authId;
	private String authPw;
	private String sendYn;
	private String referrer;
	private String subject;
	private String content;

	public String getSmtpHost()
	{
		return smtpHost;
	}

	public void setSmtpHost(String smtpHost)
	{
		this.smtpHost = smtpHost;
	}

	public String getSmtpPort()
	{
		return smtpPort;
	}

	public void setSmtpPort(String smtpPort)
	{
		this.smtpPort = smtpPort;
	}

	public String getSmtpChnl()
	{
		return smtpChnl;
	}

	public void setSmtpChnl(String smtpChnl)
	{
		this.smtpChnl = smtpChnl;
	}

	public String getSmtpAuth()
	{
		return smtpAuth;
	}

	public void setSmtpAuth(String smtpAuth)
	{
		this.smtpAuth = smtpAuth;
	}

	public String getAuthName()
	{
		return authName;
	}

	public void setAuthName(String authName)
	{
		this.authName = authName;
	}

	public String getAuthId()
	{
		return authId;
	}

	public void setAuthId(String authId)
	{
		this.authId = authId;
	}

	public String getAuthPw()
	{
		return authPw;
	}

	public void setAuthPw(String authPw)
	{
		this.authPw = authPw;
	}

	public String getSendYn()
	{
		return sendYn;
	}

	public void setSendYn(String sendYn)
	{
		this.sendYn = sendYn;
	}

	public String getReferrer()
	{
		return referrer;
	}

	public void setReferrer(String referrer)
	{
		this.referrer = referrer;
	}

	public String getSubject()
	{
		return subject;
	}

	public void setSubject(String subject)
	{
		this.subject = subject;
	}

	public String getContent()
	{
		return content;
	}

	public void setContent(String content)
	{
		this.content = content;
	}
}