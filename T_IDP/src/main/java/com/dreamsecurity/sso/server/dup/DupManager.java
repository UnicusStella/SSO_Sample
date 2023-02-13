package com.dreamsecurity.sso.server.dup;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.Map;

import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.config.SSOConfig;

public class DupManager
{
	private static DupManager instance = null;

	private static Logger log = LoggerFactory.getLogger(DupManager.class);

	private String serverIp = "";
	private int serverPort = 0;
	private int timeout = 3000;
	private int buffersize = 512;

	public static final int FLAG_PUT_LOGIN = 1;
	public static final int FLAG_PUT_LOGOUT = 2;

	public static final String CMD_PUT_LOGIN = "DPMS0001";
	public static final String CMD_PUT_LOGOUT = "DPMS0002";
	public static final String CMD_GET_PRELOGIN = "DPMS0003";

	public static DupManager getInstance()
	{
		if (instance == null) {
			synchronized (DupManager.class) {
				if (instance == null) {
					try {
						instance = new DupManager();
					}
					catch (Exception e) {
						e.printStackTrace();
					}
				}
			}
		}

		return instance;
	}

	private DupManager()
	{
		try {
			SSOConfig config = SSOConfig.getInstance();
			this.serverIp = config.getString("dup.server.ip", "");
			this.serverPort = config.getInt("dup.server.port", 0);
			this.timeout = config.getInt("dup.server.timeout", 3000);
			this.buffersize = config.getInt("dup.server.buffer", 512);
		}
		catch (Exception e) {
			log.error("### DupManager() Exception: {}", e.toString());
			e.printStackTrace();

			this.serverIp = "";
			this.serverPort = 0;
			this.timeout = 3000;
			this.buffersize = 512;
		}
	}

	private void dupInit()
	{
		if (this.serverPort == 0) {
			try {
				SSOConfig config = SSOConfig.getInstance();
				this.serverIp = config.getString("dup.server.ip", "");
				this.serverPort = config.getInt("dup.server.port", 0);
				this.timeout = config.getInt("dup.server.timeout", 3000);
				this.buffersize = config.getInt("dup.server.buffer", 1024);
			}
			catch (Exception e) {
				log.error("### DupManager.dupInit() Exception: {}", e.toString());
				e.printStackTrace();

				this.serverIp = "";
				this.serverPort = 0;
				this.timeout = 3000;
				this.buffersize = 1024;
			}
		}
	}

	public void putLogin(Map<String, String> param)
	{
		doprocess(makeSendMsg(CMD_PUT_LOGIN, param));
	}

	public void putLogout(Map<String, String> param)
	{
		doprocess(makeSendMsg(CMD_PUT_LOGOUT, param));
	}

	public String getPreLogin(Map<String, String> param)
	{
		return doprocess(makeSendMsg(CMD_GET_PRELOGIN, param));
	}

	public String makeSendMsg(String cmd, Map<String, String> param)
	{
		NumberFormat nf = new DecimalFormat("00000000");
		String reqStatus = "00000001";

		// <s0,dup,0></s0><s0,dup,1></s0>...
		String prefix = "<s0,dup,";
		String presuffix = ">";
		String suffix = "</s0>";
		int idx = 0;

		// make send body msg
		StringBuffer bodybuf = new StringBuffer();
		bodybuf.append(prefix).append(idx++).append(presuffix).append(param.get("group")).append(suffix);
		bodybuf.append(prefix).append(idx++).append(presuffix).append(param.get("uid")).append(suffix);

		if (!cmd.equals(CMD_PUT_LOGOUT)) {
			bodybuf.append(prefix).append(idx++).append(presuffix).append(param.get("uip")).append(suffix);
			bodybuf.append(prefix).append(idx++).append(presuffix).append(param.get("ubr")).append(suffix);
		}

		String bodyLen = nf.format(bodybuf.length());

		StringBuffer sendBMsg = new StringBuffer();
		StringBuffer returnSendMsg = new StringBuffer();

		sendBMsg.append(cmd);        // cmd
		sendBMsg.append(reqStatus);  // 00000001
		sendBMsg.append(bodyLen);    // bodyLen
		sendBMsg.append(bodybuf);    // bodybuf

		String totLen = nf.format(cmd.getBytes().length + reqStatus.getBytes().length + bodyLen.getBytes().length
									+ bodybuf.toString().getBytes().length);

		returnSendMsg.append(totLen);
		returnSendMsg.append("0100");
		returnSendMsg.append(sendBMsg.toString());

		return returnSendMsg.toString();
	}

	public String doprocess(String requestMessage)
	{
		String rlt = "";

		dupInit();

		if (this.serverPort == 0) {
			log.error("### No DPMS sttings.");
			return rlt;
		}

		Socket soc = null;
		OutputStreamWriter osw = null;

		try {
			soc = getSocket(this.serverIp, this.serverPort, this.timeout, this.buffersize);

			if (soc.isConnected()) {
				osw = new OutputStreamWriter(soc.getOutputStream());
				osw.write(requestMessage.toString());
				osw.flush();

				rlt = result(soc.getInputStream());
			}
		}
		catch (Exception e) {
			log.error("### DupManager.doprocess() Exception: {}", e.toString());
		}
		finally {
			if (soc != null && !soc.isClosed()) {
				try {
					soc.close();
				}
				catch (Exception e) {
					log.error("### DupManager socket close() Exception: {}", e.toString());
				}

				soc = null;
			}
		}

		return rlt;
	}

	public Socket getSocket(String serverIp, int serverPort, int timeout, int buffersize) throws IOException
	{
		Socket socket = null;

		try {
			socket = new Socket();
			socket.connect(new InetSocketAddress(serverIp, serverPort), timeout);
			socket.setReceiveBufferSize(buffersize);
		}
		catch (Exception e) {
			log.error("### connect info: {}, {}, {}, {}", serverIp, serverPort, timeout, buffersize);
			log.error("### connect error: {}", e.toString());

			if (socket != null && !socket.isClosed()) {
				socket.close();
			}

			socket = null;
		}

		if (socket == null) {
			throw new IOException("server connect failed");
		}

		return socket;
	}

	public String result(InputStream pStream) throws Exception
	{
		byte[] header = new byte[12];

		int c = pStream.read(header);

		if (c < header.length) {
			throw new IOException("### Failed to read servers response: cannot read header data(readedBytes = " + c);
		}

		int totalsize = 0;

		try {
			totalsize = Integer.parseInt(new String(header, 0, 8));
		}
		catch (NumberFormatException e) {
			throw new IOException("### Failed to read servers respose: invalid header data(SIZE[" + new String(header, 0, 8) + "]");
		}

		int readed = 0;
		ByteArrayOutputStream out = new ByteArrayOutputStream(totalsize);

		while (readed++ < totalsize) {
			out.write(pStream.read());
		}

		if (out.toByteArray().length != totalsize) {
			throw new IOException("### Failed to read servers respose:  readed size = " + out.toByteArray().length + ", headersize = " + totalsize);
		}

		return new String(out.toByteArray(), "UTF-8");
	}
}