package com.dreamsecurity.sso.server.repository.connection;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;

import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.lib.ism.client.SqlMapClient;

public class DBConnectMap
{
	private static Logger log = LoggerFactory.getLogger(DBConnectMap.class);

	private Map<String, Object> dbmap = new HashMap<String, Object>();
	public DBConnectMonitor connMonitor = null;

	private DBConnectMap()
	{
	}

	private static class dbcmSingleton
	{
		private static final DBConnectMap instance = new DBConnectMap();
	}

	public static DBConnectMap getInstance()
	{
		return dbcmSingleton.instance;
	}

	public SqlMapClient getConnection(String dbname)
	{
		return (SqlMapClient) this.dbmap.get(dbname);
	}

	public void createDBConnections()
	{
		SSOConfig config = SSOConfig.getInstance();
		String[] dbnames = config.getStringArray("object-pool.dbex[@name]");

		for (int i = 0; i < dbnames.length; i++) {
			long startTime = System.currentTimeMillis();
			int idx = config.getIndexOfProperty("object-pool.dbex", "name", dbnames[i]);

			if (config.getBoolean("object-pool.dbex(" + idx + ")[@usable]")) {
				String dbpath = config.getString("object-pool.dbex(" + idx + ").config-file");
				dbpath = config.getHomePath(dbpath);
				SqlMapClient smc = null;

				try {
					smc = new DBConnect(dbpath).getSqlMapClient();
					smc.queryForObject(dbnames[i] + "_connCheck");

					if (config.getString("repository[@type]").equalsIgnoreCase("DB")) {
						startConnectionMonitor(dbnames[i]);
					}
				}
				catch (Exception e) {
					log.error("### {}'s Connection Pool Create Failure [ {} ms.]", dbnames[i], System.currentTimeMillis() - startTime);
					e.printStackTrace();
					continue;
				}

				dbmap.put(dbnames[i], smc);
				log.debug("### {}'s Connection Pool Create Success [ {} ms.]", dbnames[i], System.currentTimeMillis() - startTime);
			}
		}

		log.info("### DBConnectMap size : {}", dbmap.size());
	}

	public void createDBConnection(String dbname)
	{
		dbmap.remove(dbname);

		long startTime = System.currentTimeMillis();

		SSOConfig config = SSOConfig.getInstance();
		int idx = config.getIndexOfProperty("object-pool.dbex", "name", dbname);

		if (config.getBoolean("object-pool.dbex(" + idx + ")[@usable]")) {
			String dbpath = config.getString("object-pool.dbex(" + idx + ").config-file");
			dbpath = config.getHomePath(dbpath);
			SqlMapClient smc = null;

			try {
				smc = new DBConnect(dbpath).getSqlMapClient();
				smc.queryForObject(dbname + "_connCheck");

				if (config.getString("repository[@type]").equalsIgnoreCase("DB")) {
					stopConnectionMonitor();
					connMonitor = null;
					startConnectionMonitor(dbname);
				}
			}
			catch (Exception e) {
				log.error("### {}'s Connection Pool Create Failure [ {} ms.]", dbname, System.currentTimeMillis() - startTime);
				e.printStackTrace();
				return;
			}

			dbmap.put(dbname, smc);
			log.error("### {}'s Connection Pool Create Success [ {} ms.]", dbname, System.currentTimeMillis() - startTime);
		}

		log.info("### DBConnectMap size : {}", dbmap.size());
	}

	private synchronized void startConnectionMonitor()
	{
		SSOConfig config = SSOConfig.getInstance();
		boolean isMonitor = SSOConfig.getInstance().getBoolean("connect.monitor[@enable]");

		if (isMonitor) {
			Iterator<String> its = this.dbmap.keySet().iterator();
			long interval = config.getLong("connect.monitor.checkinterval") * 60 * 1000;

			while (its.hasNext()) {
				String dbname = its.next();

				DBConnectMonitor cm = new DBConnectMonitor(dbname);
				cm.setContinue(true);
				cm.setInterval(interval);

				Thread monitor = new Thread(cm);
				monitor.setPriority(Thread.MAX_PRIORITY);
				monitor.start();
			}
		}
	}

	private synchronized void startConnectionMonitor(String dbname)
	{
		SSOConfig config = SSOConfig.getInstance();
		boolean isMonitor = config.getBoolean("connect.monitor[@enable]");

		if (isMonitor) {
			long interval = config.getLong("connect.monitor.checkinterval") * 60;

			connMonitor = new DBConnectMonitor(dbname);
			connMonitor.setContinue(true);
			connMonitor.setInterval(interval);

			Thread monitor = new Thread(connMonitor);
			monitor.setPriority(Thread.MAX_PRIORITY);
			monitor.start();
		}
	}

	public void stopConnectionMonitor()
	{
		if (connMonitor != null) {
			connMonitor.setContinue(false);
		}
	}
}