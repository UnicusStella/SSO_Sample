package com.dreamsecurity.sso.agent.ha;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

public class SyncEvent implements Externalizable
{
	private int eventid;
	private long timestamp;
	private String key;
	private String value;

	public static final int EVENT_INTEGRITY = 0;
	public static final int EVENT_LOGIN = 1;
	public static final int EVENT_LOGOUT = 2;
	public static final int EVENT_SET_CHLG = 3;
	public static final int EVENT_DEL_CHLG = 4;

	public SyncEvent()
	{
	}

	public SyncEvent(int eventid, long timestamp, String key, String value)
	{
		this.eventid = eventid;
		this.timestamp = timestamp;
		this.key = key;
		this.value = value;
	}

	public int getEventid()
	{
		return eventid;
	}

	public long getTimestamp()
	{
		return timestamp;
	}

	public String getKey()
	{
		return key;
	}

	public String getValue()
	{
		return value;
	}

	@Override
	public String toString()
	{
		return "SyncEvent [eventid=" + eventid + ", timestamp=" + timestamp + ", key=" + key + ", value=" + value + "]";
	}

	public void writeExternal(ObjectOutput out) throws IOException
	{
		out.writeInt(eventid);
		out.writeLong(timestamp);
		out.writeObject(key);
		out.writeObject(value);
	}

	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException
	{
		eventid = in.readInt();
		timestamp = in.readLong();
		key = (String) in.readObject();
		value = (String) in.readObject();
	}
}
