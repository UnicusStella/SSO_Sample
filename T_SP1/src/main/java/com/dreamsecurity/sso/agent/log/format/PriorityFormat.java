package com.dreamsecurity.sso.agent.log.format;

import com.dreamsecurity.sso.agent.log.DefaultLoggerImpl;

class PriorityFormat implements TypeFormater
{
	boolean isFullName = true;

	public String format(int type)
	{
        switch(type) {
            case DefaultLoggerImpl.LOG_LEVEL_TRACE: return (isFullName ? "TRACE":"T"); 
            case DefaultLoggerImpl.LOG_LEVEL_DEBUG: return (isFullName ? "DEBUG":"D"); 
            case DefaultLoggerImpl.LOG_LEVEL_INFO:  return (isFullName ? "INFO":"I");  
            case DefaultLoggerImpl.LOG_LEVEL_WARN:  return (isFullName ? "WARN":"W");  
            case DefaultLoggerImpl.LOG_LEVEL_ERROR: return (isFullName ? "ERROR":"E"); 
            case DefaultLoggerImpl.LOG_LEVEL_FATAL: return (isFullName ? "FATAL":"F"); 
        }
        
        return isFullName ? "INFO":"I";
	}


	PriorityFormat( boolean isFullName)
	{
		this.isFullName = isFullName;
	}
}