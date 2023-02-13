package com.dreamsecurity.sso.server.repository.connection;

import java.io.FileReader;
import java.io.Reader;
import java.util.Properties;

import com.dreamsecurity.sso.lib.ism.client.SqlMapClient;
import com.dreamsecurity.sso.lib.ism.client.SqlMapClientBuilder;
import com.dreamsecurity.sso.server.config.SSOConfig;

public class DBConnect
{
	private SqlMapClient sqlMap = null;

	public DBConnect(String dbpath) throws Exception
	{
		Reader reader = null;

		try {
			if (sqlMap == null) {
				SSOConfig config = SSOConfig.getInstance();
				String drv = config.getStringProperty("dbcp.driver", "");
				String url = config.getStringProperty("dbcp.url", "");
				String usr = config.getStringProperty("dbcp.username", "");
				String pwd = config.getStringProperty("dbcp.password", "");

				Properties properties = new Properties();
				properties.setProperty("dbcp.driver", drv);
				properties.setProperty("dbcp.url", url);
				properties.setProperty("dbcp.username", usr);
				properties.setProperty("dbcp.password", pwd);

				//reader = Resources.getResourceAsReader(dbpath);
				reader = new FileReader(dbpath);

				sqlMap = SqlMapClientBuilder.buildSqlMapClient(reader, properties);

				reader.close();
			}
		}
		catch (Exception e) {
			if (reader != null) {
				reader.close();
				reader = null;
			}

			throw e;
		}
	}

	public SqlMapClient getSqlMapClient()
	{
		return sqlMap;
	}
}