package com.dreamsecurity.sso.agent.log;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import com.dreamsecurity.sso.agent.config.SSOConfig;

public class LoggerFactory
{
	static protected final String logPrefix = "logger.";

	private static LoggerFactory instance = null;

	public static LoggerFactory getInstance()
	{
		if (instance == null) {
			synchronized (LoggerFactory.class) {
				if (instance == null) {
					instance = new LoggerFactory();
				}
			}
		}

		return instance;
	}

	private SSOConfig config;
	private LogWriter[] writers;

	private LoggerFactory()
	{
		config = SSOConfig.getInstance();
		writers = null;

		try {
			setConfig(config);
		}
		catch (IOException ioe) {
			ioe.printStackTrace();
		}
	}

	public void setConfig(SSOConfig config) throws IOException
	{
		this.config = config;
		this.writers = discoverLogWriters();
	}

	public Logger getLogger(String name)
	{
		DefaultLoggerImpl logger = new DefaultLoggerImpl(name);

		logger.setWriters(writers);
		logger.setLevel(getLevel(name));

		return logger;
	}

	public Logger getLogger(Class<?> cls)
	{
		return getLogger(cls.getName());
	}

	private int getLevel(String name)
	{
		int level = DefaultLoggerImpl.LOG_LEVEL_INFO;

		String lvl = config.getString(logPrefix + "level." + name);

		if (lvl == null || lvl.equals("")) {
			lvl = config.getString(logPrefix + "level.default");
		}

		if ("all".equalsIgnoreCase(lvl)) {
			level = (DefaultLoggerImpl.LOG_LEVEL_ALL);
		}
		else if ("trace".equalsIgnoreCase(lvl)) {
			level = (DefaultLoggerImpl.LOG_LEVEL_TRACE);
		}
		else if ("debug".equalsIgnoreCase(lvl)) {
			level = (DefaultLoggerImpl.LOG_LEVEL_DEBUG);
		}
		else if ("info".equalsIgnoreCase(lvl)) {
			level = (DefaultLoggerImpl.LOG_LEVEL_INFO);
		}
		else if ("warn".equalsIgnoreCase(lvl)) {
			level = (DefaultLoggerImpl.LOG_LEVEL_WARN);
		}
		else if ("error".equalsIgnoreCase(lvl)) {
			level = (DefaultLoggerImpl.LOG_LEVEL_ERROR);
		}
		else if ("fatal".equalsIgnoreCase(lvl)) {
			level = (DefaultLoggerImpl.LOG_LEVEL_FATAL);
		}
		else if ("off".equalsIgnoreCase(lvl)) {
			level = (DefaultLoggerImpl.LOG_LEVEL_OFF);
		}

		if (config.isVerbose()) {
			String levelName = "";
			switch (level) {
			case 0:
				levelName = "ALL";
				break;
			case 1:
				levelName = "TRACE";
				break;
			case 2:
				levelName = "DEBUG";
				break;
			case 3:
				levelName = "INFO";
				break;
			case 4:
				levelName = "WARN";
				break;
			case 5:
				levelName = "ERROR";
				break;
			case 6:
				levelName = "FATAL";
				break;
			case 7:
				levelName = "OFF";
				break;
			default:
				levelName = "UNDEFINED";
			}
			System.out.println(new StringBuffer("LoggerFactory -> getLevel() [V]  - LOG_LEVEL =  " + levelName));
		}

		return level;
	}

	private LogWriter[] discoverLogWriters() throws IOException
	{
		List<Object> list = config.getList("logger");
		String loggers[] = new String[list.size()];
		list.toArray(loggers);

		ArrayList<Object> array = new ArrayList<Object>();

		for (int i = 0; i < loggers.length; i++) {
			array.add(discoverImplementation(discoverParameter(loggers[i].trim())));  // log1, log2가 들어감

			if (config.isVerbose())
				System.out.println(new StringBuffer("LoggerFactory -> discoverLogWriters() [V]  - loggers[" + i + "] : " + loggers[i]));
		}

		LogWriter[] writers = new LogWriter[array.size()];
		array.toArray(writers);

		if (config.isVerbose())
			System.out.println(new StringBuffer("LoggerFactory -> discoverLogWriters() [V]  - writers.length : " + writers.length));

		return writers;
	}

	private LogWriter discoverImplementation(Map<String, String> param)
	{
		String className = (String) param.get("classname");
		LogWriter writer;

		try {
			Class<?> cls = Class.forName(className);
			writer = (LogWriter) cls.newInstance();
			writer.initLogger(param);
			return writer;
		}
		catch (Throwable t) {
			t.printStackTrace();
			throw new IllegalArgumentException(t.getMessage());
		}
	}

	private Map<String, String> discoverParameter(String loggerName)
	{
		if (config.isVerbose()) {
			System.out.println(new StringBuffer("LoggerFactory -> discoverParameter() [V]  - loggerName : ").append(loggerName).toString());
		}

		Map<String, String> map = new HashMap<String, String>();
		String id = logPrefix + loggerName;
		String classname = config.getString(id);
		map.put("classname", classname);
		String value = null;

		for (Iterator<String> keys = config.getKeys(id); keys.hasNext();) {
			String key = (String) keys.next();

			if (key.startsWith(id + ".")) {
				String name = key.substring(id.length() + 1);
				value = config.getString(key);
				map.put(name, value);
				if (config.isVerbose()) {
					System.out.println(new StringBuffer("LoggerFactory [V]  - name : ").append(name).append(" || value : ").append(value).toString());
				}
			}

			// map.put("home.dir", config.getHomeDir());
			map.put("home.dir", config.getString("logger.root.dir"));
		}

		return map;
	}
}