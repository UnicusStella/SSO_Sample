package com.dreamsecurity.sso.agent.log;

import java.io.Serializable;

import com.dreamsecurity.sso.agent.log.DefaultLoggerImpl;
import com.dreamsecurity.sso.agent.log.LogWriter;
import com.dreamsecurity.sso.agent.log.Logger;

public class DefaultLoggerImpl implements Logger, Serializable
{
	/**
	 * 
	 */
	private static final long serialVersionUID = 845438877457936245L;

	// ---------------------------------------------------- Log Level Constants
	public static final int LOG_LEVEL_TRACE = 1;

	public static final int LOG_LEVEL_DEBUG = 2;

	public static final int LOG_LEVEL_INFO = 3;

	public static final int LOG_LEVEL_WARN = 4;

	public static final int LOG_LEVEL_ERROR = 5;

	public static final int LOG_LEVEL_FATAL = 6;

	public static final int LOG_LEVEL_ALL = (LOG_LEVEL_TRACE - 1);

	public static final int LOG_LEVEL_OFF = (LOG_LEVEL_FATAL + 1);

	// ------------------------------------------------------------ Initializer

	// ------------------------------------------------------------- Attributes

	protected String logName = null;

	protected int currentLogLevel;

	private String shortLogName = null;

	private LogWriter[] writers = null;

	// ------------------------------------------------------------ Constructor

	public DefaultLoggerImpl(String name)
	{
		logName = name;

		// Cut all but the last component of the name for both styles
		shortLogName = logName.substring(logName.lastIndexOf(".") + 1);
		shortLogName = shortLogName.substring(shortLogName.lastIndexOf("/") + 1);
	}

	// -------------------------------------------------------- Properties

	public void setLevel(int currentLogLevel)
	{
		this.currentLogLevel = currentLogLevel;
	}

	public int getLevel()
	{
		return currentLogLevel;
	}

	public void setWriters(LogWriter[] writers)
	{
		this.writers = writers;
	}

	// -------------------------------------------------------- Logging Methods

	protected void log(int type, Object message, Throwable t)
	{
		// Use a string buffer for better performance
		StringBuffer buf = new StringBuffer();

		// Append the message
		buf.append(String.valueOf(message));

		// Append stack trace if not null
		if (t != null) {
			buf.append(" <");
			buf.append(t.toString());
			buf.append(">");

			java.io.StringWriter sw = new java.io.StringWriter(1024);
			java.io.PrintWriter pw = new java.io.PrintWriter(sw);
			t.printStackTrace(pw);
			pw.close();
			buf.append(sw.toString());
		}

		write(type, buf);
	}

	protected void write(int type, StringBuffer buffer)
	{
		for (int i = 0; i < writers.length; i++) {
			writers[i].write(type, buffer.toString());
		}
	}

	protected boolean isLevelEnabled(int logLevel)
	{
		return (logLevel >= currentLogLevel);
	}

	public final void debug(Object message)
	{
		if (isLevelEnabled(DefaultLoggerImpl.LOG_LEVEL_DEBUG)) {
			log(DefaultLoggerImpl.LOG_LEVEL_DEBUG, message, null);
		}
	}

	public final void debug(Object message, Throwable t)
	{
		if (isLevelEnabled(DefaultLoggerImpl.LOG_LEVEL_DEBUG)) {
			log(DefaultLoggerImpl.LOG_LEVEL_DEBUG, message, t);
		}
	}

	public final void trace(Object message)
	{
		if (isLevelEnabled(DefaultLoggerImpl.LOG_LEVEL_TRACE)) {
			log(DefaultLoggerImpl.LOG_LEVEL_TRACE, message, null);
		}
	}

	public final void trace(Object message, Throwable t)
	{
		if (isLevelEnabled(DefaultLoggerImpl.LOG_LEVEL_TRACE)) {
			log(DefaultLoggerImpl.LOG_LEVEL_TRACE, message, t);
		}
	}

	public final void info(Object message)
	{
		if (isLevelEnabled(DefaultLoggerImpl.LOG_LEVEL_INFO)) {
			log(DefaultLoggerImpl.LOG_LEVEL_INFO, message, null);
		}
	}

	public final void info(Object message, Throwable t)
	{
		if (isLevelEnabled(DefaultLoggerImpl.LOG_LEVEL_INFO)) {
			log(DefaultLoggerImpl.LOG_LEVEL_INFO, message, t);
		}
	}

	public final void warn(Object message)
	{
		if (isLevelEnabled(DefaultLoggerImpl.LOG_LEVEL_WARN)) {
			log(DefaultLoggerImpl.LOG_LEVEL_WARN, message, null);
		}
	}

	public final void warn(Object message, Throwable t)
	{
		if (isLevelEnabled(DefaultLoggerImpl.LOG_LEVEL_WARN)) {
			log(DefaultLoggerImpl.LOG_LEVEL_WARN, message, t);
		}
	}

	public final void error(Object message)
	{
		if (isLevelEnabled(DefaultLoggerImpl.LOG_LEVEL_ERROR)) {
			log(DefaultLoggerImpl.LOG_LEVEL_ERROR, message, null);
		}
	}

	public final void error(Object message, Throwable t)
	{
		if (isLevelEnabled(DefaultLoggerImpl.LOG_LEVEL_ERROR)) {
			log(DefaultLoggerImpl.LOG_LEVEL_ERROR, message, t);
		}
	}

	public final void fatal(Object message)
	{
		if (isLevelEnabled(DefaultLoggerImpl.LOG_LEVEL_FATAL)) {
			log(DefaultLoggerImpl.LOG_LEVEL_FATAL, message, null);
		}
	}

	public final void fatal(Object message, Throwable t)
	{
		if (isLevelEnabled(DefaultLoggerImpl.LOG_LEVEL_FATAL)) {
			log(DefaultLoggerImpl.LOG_LEVEL_FATAL, message, t);
		}
	}

	public final boolean isDebugEnabled()
	{
		return isLevelEnabled(DefaultLoggerImpl.LOG_LEVEL_DEBUG);
	}

	public final boolean isErrorEnabled()
	{
		return isLevelEnabled(DefaultLoggerImpl.LOG_LEVEL_ERROR);
	}

	public final boolean isFatalEnabled()
	{
		return isLevelEnabled(DefaultLoggerImpl.LOG_LEVEL_FATAL);
	}

	public final boolean isInfoEnabled()
	{
		return isLevelEnabled(DefaultLoggerImpl.LOG_LEVEL_INFO);
	}

	public final boolean isTraceEnabled()
	{
		return isLevelEnabled(DefaultLoggerImpl.LOG_LEVEL_TRACE);
	}

	public final boolean isWarnEnabled()
	{
		return isLevelEnabled(DefaultLoggerImpl.LOG_LEVEL_WARN);
	}
}