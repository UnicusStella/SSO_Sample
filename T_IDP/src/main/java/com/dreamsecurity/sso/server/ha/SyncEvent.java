package com.dreamsecurity.sso.server.ha;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

import com.dreamsecurity.sso.lib.jtm.DateTime;
import com.dreamsecurity.sso.lib.jtm.DateTimeZone;
import com.dreamsecurity.sso.server.session.RootAuthSession;
import com.dreamsecurity.sso.server.token.OAuth2Code;

public class SyncEvent implements Externalizable
{
	private int eventid;
	private long timestamp;
	private String detail;
	private String id;
	private String providerId;
	private DateTime issueInstant;
	private String authnContextClassRef;
	private String provSessionId;
	private String authnInfo;
	private String authcode;
	private String deviceType;
	private String deviceId;
	private String blockId;

	//OIDC
	private RootAuthSession rootAuthSession;
	private OAuth2Code oauth2Code;
	private String rootAuthSessionId;

	public SyncEvent()
	{
	}

	public SyncEvent(int eventid, long timestamp, String detail, String id, String providerId, DateTime issueInstant, String authnContextClassRef,
			String provSessionId, String authnInfo, String authcode, String deviceType, String deviceId, String blockId,
			RootAuthSession rootAuthSession, OAuth2Code oauth2Code, String rootAuthSessionId)
	{
		this.eventid = eventid;
		this.timestamp = timestamp;
		this.detail = detail;
		this.id = id;
		this.providerId = providerId;
		this.issueInstant = issueInstant;
		this.authnContextClassRef = authnContextClassRef;
		this.provSessionId = provSessionId;
		this.authnInfo = authnInfo;
		this.authcode = authcode;
		this.deviceType = deviceType;
		this.deviceId = deviceId;
		this.blockId = blockId;
		this.rootAuthSession = rootAuthSession;
		this.oauth2Code = oauth2Code;
		this.rootAuthSessionId = rootAuthSessionId;
	}

	public int getEventid()
	{
		return eventid;
	}

	public long getTimestamp()
	{
		return timestamp;
	}

	public String getDetail()
	{
		return detail;
	}

	public String getId()
	{
		return id;
	}

	public String getProviderId()
	{
		return providerId;
	}

	public DateTime getIssueInstant()
	{
		return issueInstant;
	}

	public String getAuthnContextClassRef()
	{
		return authnContextClassRef;
	}

	public String getProvSessionId()
	{
		return provSessionId;
	}

	public String getAuthnInfo()
	{
		return authnInfo;
	}

	public String getAuthcode()
	{
		return authcode;
	}

	public String getDeviceType()
	{
		return deviceType;
	}

	public String getDeviceId()
	{
		return deviceId;
	}

	public String getBlockId()
	{
		return blockId;
	}

	public RootAuthSession getRootAuthSession()
	{
		return rootAuthSession;
	}

	public OAuth2Code getOauth2Code()
	{
		return oauth2Code;
	}

	public String getRootAuthSessionId()
	{
		return rootAuthSessionId;
	}

	@Override
	public String toString()
	{
		return "SyncEvent [eventid=" + eventid + ", timestamp=" + timestamp + ", detail=" + detail + ", id=" + id + ", providerId=" + providerId
				+ ", issueInstant=" + issueInstant + ", authnContextClassRef=" + authnContextClassRef + ", provSessionId=" + provSessionId
				+ ", authnInfo=" + authnInfo + ", authcode=" + authcode + ", deviceType=" + deviceType + ", deviceId=" + deviceId + ", blockId="
				+ blockId + ", rootAuthSessionId=" + rootAuthSessionId + "]";
	}

	public void writeExternal(ObjectOutput out) throws IOException
	{
		out.writeInt(eventid);
		out.writeLong(timestamp);
		out.writeObject(detail);
		out.writeObject(id);
		out.writeObject(providerId);
		out.writeLong(issueInstant.getMillis());
		out.writeObject(authnContextClassRef);
		out.writeObject(provSessionId);
		out.writeObject(authnInfo);
		out.writeObject(authcode);
		out.writeObject(deviceType);
		out.writeObject(deviceId);
		out.writeObject(blockId);
		out.writeObject(rootAuthSession);
		out.writeObject(oauth2Code);
		out.writeObject(rootAuthSessionId);
	}

	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException
	{
		eventid = in.readInt();
		timestamp = in.readLong();
		detail = (String) in.readObject();
		id = (String) in.readObject();
		providerId = (String) in.readObject();
		issueInstant = new DateTime(in.readLong()).withZone(DateTimeZone.UTC);
		authnContextClassRef = (String) in.readObject();
		provSessionId = (String) in.readObject();
		authnInfo = (String) in.readObject();
		authcode = (String) in.readObject();
		deviceType = (String) in.readObject();
		deviceId = (String) in.readObject();
		blockId = (String) in.readObject();
		rootAuthSession = (RootAuthSession) in.readObject();
		oauth2Code = (OAuth2Code) in.readObject();
		rootAuthSessionId = (String) in.readObject();
	}
}