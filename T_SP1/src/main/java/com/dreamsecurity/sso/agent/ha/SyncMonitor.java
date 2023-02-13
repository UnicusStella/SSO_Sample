package com.dreamsecurity.sso.agent.ha;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.dreamsecurity.sso.agent.config.SSOConfig;
import com.dreamsecurity.sso.agent.log.Logger;
import com.dreamsecurity.sso.agent.log.LoggerFactory;
import com.dreamsecurity.sso.agent.util.Util;

public class SyncMonitor implements Runnable
{
	private static Logger log = LoggerFactory.getInstance().getLogger(SyncMonitor.class);

	private static final SyncMonitor instance = new SyncMonitor();

	int port = 0;
	List<?> ipList;

	boolean isReady = false;
 
	private SyncMonitor()
	{
		SSOConfig config = SSOConfig.getInstance();

		port = config.getInt("ha.listen.port", 0);
		ipList = config.getList("ha.send.ip", null);

		if (ipList == null) {
			port = 0;
		}
		else {
			if (ipList.size() == 1 && Util.isEmpty((String) ipList.get(0))) {
				port = 0;
			}
			else {
				log.debug("### Sync IP   : " + this.ipList.toString());
				log.debug("### Sync Port : " + this.port);
			}
		}

		startMapMonitor();
	}

	public static void startMonitor()
	{
		if (instance.port == 0) {
			return;
		}

		if (!instance.isReady) {
			synchronized (instance) {
				if (!instance.isReady) {
					log.debug("### SyncMonitor Start");
					new Thread(instance).start();
				}
			}
		}
	}

	public void run()
	{
		ServerSocket serverSocket = null;

		try {
			serverSocket = new ServerSocket(port);

			while (true) {
				Socket socket = serverSocket.accept();
				process(socket);
				isReady = true;
			}
		}
		catch (Exception e) {
			// e.printStackTrace();
		}
		finally {
			try {
				if (serverSocket != null) {
					serverSocket.close();
				}
			}
			catch (IOException e) {
				// e.printStackTrace();
			}

			isReady = false;
		}
	}

	private void process(Socket socket)
	{
		try {
			ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());
			SyncEvent event = (SyncEvent) inputStream.readObject();
			SyncManager.getInstance().applyEvents(event);
			socket.close();
		}
		catch (Exception e) {
			//log.debug("### logoutEvent receive fail", e);
		}
	}

	public static void sendEvent(final SyncEvent event)
	{
		if (instance.port == 0) {
			return;
		}

		for (int i = 0; i < instance.ipList.size(); i++) {
			log.debug("### sendEvent() Data : " + event.toString());

			final String ip = (String) instance.ipList.get(i);
			log.debug("### sendEvent() IP[" + i + "] : " + ip);

			if (Util.isEmpty(ip)) {
				continue;
			}

			new Thread()
			{
				public void run()
				{
					try {
						Socket socket = new Socket();
						socket.connect(new InetSocketAddress(ip, instance.port), 3000);
						ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
						outputStream.writeObject(event);
						socket.close();
					}
					catch (IOException e) {
						log.debug("### sendEvent() Exception : ", e);
					}
				}
			}.start();
		}
	}

	private synchronized void startMapMonitor()
	{
		MapMonitor mm = new MapMonitor();
		mm.setContinue(true);
		mm.setInterval(60);
		Thread monitor = new Thread(mm);
		monitor.setPriority(Thread.MAX_PRIORITY);
		monitor.start();
	}
}

class MapMonitor implements Runnable
{
	private static Logger log = LoggerFactory.getInstance().getLogger(MapMonitor.class);

	private boolean isContinue;
	private long interval;
	private String arrangeWork = "";
	private static final String SEPARATOR = "^@^";

	public MapMonitor()
	{
	}

	public void setContinue(boolean isContinue)
	{
		this.isContinue = isContinue;
	}

	public void setInterval(long interval)  // minute
	{
		this.interval = interval * 60 * 1000;
	}

	public void run()
	{
		log.debug("### Map Monitor Start ...");

		while (this.isContinue) {
			try {
				Thread.sleep(this.interval);
				log.debug("### Map Monitor Check ...");
			}
			catch (InterruptedException e) {
				e.printStackTrace();
			}

			arrangeMap();
		}

		log.debug("### Map Monitor Stop ...");
	}

	private void arrangeMap()
	{
		try {
			String arrangeTime = "04";  //SSOConfig.getInstance().getProperty("map.arrange.time");

			SimpleDateFormat ddhhFormat = new SimpleDateFormat("ddHH");
			SimpleDateFormat hhFormat = new SimpleDateFormat("HH");
			String curDateHour = ddhhFormat.format(new Date());
			String curHour = hhFormat.format(new Date());

			if (!arrangeTime.equals(curHour) || arrangeWork.equals(curDateHour)) {
				return;
			}
			else {
				arrangeWork = curDateHour;
			}

			log.debug("### Challenge Map Arrange Start");
			long startTime = System.currentTimeMillis();

			Map<String, String> challengeMap = SyncManager.getInstance().getChallengeMap();

			Iterator<Entry<String, String>> ch_iter = challengeMap.entrySet().iterator();

			while (ch_iter.hasNext()) {
				Entry<String, String> entry = (Entry<String, String>) ch_iter.next();
				String value = (String) entry.getValue();
				String valueTime;

				int idx = -1;
				if ((idx = value.indexOf(SEPARATOR)) >= 0) {
					valueTime = value.substring(idx + 3);
				}
				else {
					continue;
				}

				if (Util.isEmpty(valueTime)) {
					continue;
				}

				try {
					long validTime = Long.parseLong(valueTime) + (5 * 60 * 1000);
					long curTime = System.currentTimeMillis();
	
					if (validTime < curTime) {
						ch_iter.remove();
					}
				}
				catch (Exception e) {
					log.error("### parseLong() Exception : " + entry.getKey() + "=" + value);
				}
			}

			log.debug("### Challenge Map Arrange End [" + (System.currentTimeMillis() - startTime) + " ms.]");
		}
		catch (Exception e) {
			log.error("### arrangeMap() Exception : " + e.toString());
		}
	}
}
