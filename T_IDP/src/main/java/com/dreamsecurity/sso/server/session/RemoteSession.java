package com.dreamsecurity.sso.server.session;

import java.io.Serializable;

import com.dreamsecurity.sso.lib.jtm.DateTime;
import com.dreamsecurity.sso.lib.dss.s2.core.Assertion;
import com.dreamsecurity.sso.lib.dss.s2.core.AuthnContextClassRef;
import com.dreamsecurity.sso.lib.dss.s2.core.AuthnRequest;
import com.dreamsecurity.sso.lib.dss.s2.core.AuthnStatement;

public class RemoteSession implements Serializable
{
	private static final long serialVersionUID = 4041698414809695271L;

	private String providerId;
	private DateTime issueInstant;
	private String authnContextClassRef;
	private String provSessionId;

	public RemoteSession(String providerName, Assertion assertion, String provSessionId)
	{
		this.providerId = providerName;
		this.issueInstant = assertion.getIssueInstant();
		// support 1.4 mod
		this.authnContextClassRef = ((AuthnStatement) assertion.getAuthnStatements().get(0)).getAuthnContext().getAuthnContextClassRef()
				.getAuthnContextClassRef();
		this.provSessionId = provSessionId;
	}

	public RemoteSession(String providerName, DateTime issueInstant, String authnContextClassRef, String provSessionId)
	{
		this.providerId = providerName;
		this.issueInstant = issueInstant;
		this.authnContextClassRef = authnContextClassRef;
		this.provSessionId = provSessionId;
	}

	public RemoteSession(AuthnRequest authnRequest, String provSessionId)
	{
		this.providerId = authnRequest.getProviderName();
		this.issueInstant = authnRequest.getIssueInstant();
		// support 1.4 mod
		this.authnContextClassRef = ((AuthnContextClassRef) authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs().get(0))
				.getAuthnContextClassRef();
		this.provSessionId = provSessionId;
	}

	public String getProviderId()
	{
		return providerId;
	}

	public String getProvSessionId()
	{
		return provSessionId;
	}

	public DateTime getIssueInstant()
	{
		return issueInstant;
	}

	public String getAuthnContextClassRef()
	{
		return authnContextClassRef;
	}
}