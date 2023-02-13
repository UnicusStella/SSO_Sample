package com.dreamsecurity.sso.server.repository.ldap.pool;

import org.xml.sax.helpers.DefaultHandler;

import com.dreamsecurity.sso.lib.cdg.Digester;
import com.dreamsecurity.sso.lib.cdg.xmlrules.DigesterLoader;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.repository.connection.DBConnectMonitor;
import com.dreamsecurity.sso.server.repository.ldap.util.ResourceUtil;

public class LdapPoolLoader extends DefaultHandler
{
	private static Logger log = LoggerFactory.getLogger(LdapPoolLoader.class);

	private static LdapPoolLoader instance = null;

	public DBConnectMonitor connMonitor = null;

	private LdapPoolLoader()
	{
	}

	public static LdapPoolLoader getInstance()
	{
		if (instance == null) {
			synchronized (LdapPoolLoader.class) {
				if (instance == null) {
					try {
						instance = new LdapPoolLoader();
					}
					catch (Exception e) {
						e.printStackTrace();
					}
				}
			}
		}

		return instance;
	}

	public void createLdapPools()
	{
		SSOConfig config = SSOConfig.getInstance();
		String[] ldapnames = config.getStringArray("object-pool.ldap[@name]");

		for (int i = 0; i < ldapnames.length; i++) {
			int idx = config.getIndexOfProperty("object-pool.ldap", "name", ldapnames[i]);

			if (config.getBoolean("object-pool.ldap(" + idx + ")[@usable]")) {
				String rulefile = config.getString("object-pool.ldap(" + idx + ").digester-rule-file");
				String configfile = config.getString("object-pool.ldap(" + idx + ").config-file");

				createLdapPool(ldapnames[i], rulefile, configfile);
			}
		}

		if (ldapnames.length > 0) {
			startConnectionMonitor("LDAP");
		}
	}

	private static void createLdapPool(String poolName, String rulefile, String configfile)
	{
		try {
			Digester digester = DigesterLoader.createDigester(ResourceUtil.getInputSource(rulefile));
			LdapPool ldapPool = (LdapPool) digester.parse(ResourceUtil.getInputSource(configfile));

			LdapPoolManager.getInstance().addPool(poolName, ldapPool);
		}
		catch (Exception e) {
			log.error("### LdapPoolLoader createLdapPool() Exception: {}", e.getMessage());
			e.printStackTrace();
		}

		return;
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