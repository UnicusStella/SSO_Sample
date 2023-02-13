package com.dreamsecurity.sso.agent.log.format;

import com.dreamsecurity.sso.agent.log.format.Formater;

public interface InstanceFormater extends Formater
{
	public String format(StackTraceElement trace);
}
