package com.dreamsecurity.sso.agent.log.format;

import com.dreamsecurity.sso.agent.log.format.Formater;

public interface TypeFormater extends Formater
{
	public String format(int type);
}
