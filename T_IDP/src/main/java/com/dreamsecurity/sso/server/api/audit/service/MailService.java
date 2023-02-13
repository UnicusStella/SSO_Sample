package com.dreamsecurity.sso.server.api.audit.service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import com.dreamsecurity.sso.lib.jml.Authenticator;
import com.dreamsecurity.sso.lib.jml.Message;
import com.dreamsecurity.sso.lib.jml.PasswordAuthentication;
import com.dreamsecurity.sso.lib.jml.Session;
import com.dreamsecurity.sso.lib.jml.Transport;
import com.dreamsecurity.sso.lib.jml.internet.InternetAddress;
import com.dreamsecurity.sso.lib.jml.internet.MimeMessage;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.api.audit.vo.MailVO;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.util.Util;

public class MailService implements Runnable
{
	private static Logger log = LoggerFactory.getLogger(MailService.class);

	private String host = "";
	private String port = "";
	private String chnl = "";
	private String auth = "";
	private String auid = "";
	private String aupw = "";

	private String mailcode = "";
	private List<String> recipient = null;
	private String referrer = "";
	private String subject = "";
	private String content = "";

	public MailService()
	{
		host = "";
		port = "";
		chnl = "";
		auth = "";
		auid = "";
		aupw = "";
	}

	public MailService(MailVO mailInfo)
	{
		host = mailInfo.getSmtpHost();
		port = mailInfo.getSmtpPort();
		chnl = mailInfo.getSmtpChnl();
		auth = mailInfo.getSmtpAuth();
		auid = mailInfo.getAuthId();
		aupw = mailInfo.getAuthPw();
	}

	public void setContent(String mailcode, List<String> recipient, String referrer, String subject, String content)
	{
		this.mailcode = mailcode;
		this.recipient = recipient;
		this.referrer = referrer;
		this.subject = subject;
		this.content = content;
	}

	public void run()
	{
		String detail = "";
		if (mailcode.equals("MSND0000"))
			detail = "인증 기능 비활성화 알림";
		else if (mailcode.equals("MSND0001"))
			detail = "SSO모듈 무결성 검증 오류 알림";
		else if (mailcode.equals("MSND0002"))
			detail = "암호모듈 자가시험 오류 알림";
		else if (mailcode.equals("MSND0003"))
			detail = "감사정보 저장용량 임계치 초과 알림";
		else if (mailcode.equals("MSND0004"))
			detail = "감사정보 저장소 포화상태 알림";
		else if (mailcode.equals("MSND0005"))
			detail = "SSO 프로세스 검증 오류 알림";

		try {
			sendMail();

			if (!mailcode.equals("MSND0004")) {
				Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), SSOConfig.getInstance().getServerName(),
						"AY", "0", detail);
			}

			if (mailcode.equals("MSND0003")) {
				SSOConfig.getInstance().setDbCriticalMail(false);
			}
		}
		catch (Exception e) {
			Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), SSOConfig.getInstance().getServerName(),
					"AY", "1", detail);

			log.error("### sendMail() Exception : {}", e.getMessage());
			e.printStackTrace();
		}

		return;
	}

	public void sendTest(String smtpHost, String smtpPort, String smtpChnl, String smtpAuth, String authId, String authPw) throws Exception
	{
		String mail_subject = "SSO 메일 발송 테스트입니다.";
		String mail_content = "SSO 메일 발송 테스트입니다.";

		Properties props = System.getProperties();
		props.put("mail.smtp.host", smtpHost);
		props.put("mail.smtp.port", smtpPort);

		if (smtpChnl.equals("TLS")) {
			props.put("mail.smtp.starttls.enable", "true");
		}
		else if (smtpChnl.equals("SSL")) {
			props.put("mail.smtp.socketFactory.port", smtpPort);
			props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
		}
		else {
			props.put("mail.smtp.starttls.enable", "true");
			props.put("mail.smtp.socketFactory.port", smtpPort);
			props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
		}

		//props.put("mail.smtp.connectiontimeout", "10000");
		//props.put("mail.smtp.timeout", "10000");
		//props.put("mail.transport.protocol", "smtp");
		//props.put("mail.smtp.quitwait", "false");
		//props.put("mail.smtp.socketFactory.fallback", "false");

		if (smtpAuth.equals("Y"))
			props.put("mail.smtp.auth", "true");
		else
			props.put("mail.smtp.auth", "false");

		MyAuthenticator auth = new MyAuthenticator(authId, authPw);

		Session msession = Session.getInstance(props, auth);
		//msession.setDebug(true);

		MimeMessage msg = new MimeMessage(msession);
		msg.setFrom(new InternetAddress(authId, "SSO 시스템", "utf-8"));
		msg.addRecipient(Message.RecipientType.TO, new InternetAddress(authId, "", "utf-8"));
		msg.setSubject(mail_subject, "utf-8");
		msg.setContent(mail_content, "text/plain; charset=utf-8");

   	    Transport.send(msg);
    }

	public void sendTest(List<String> recipient, String subject, String content) throws Exception
	{
		if (recipient.size() == 0 || subject == null || content == null) {
			return;
		}

		if (referrer == null){
			referrer = "";
		}

		Properties props = System.getProperties();
		props.put("mail.smtp.host", this.host);
		props.put("mail.smtp.port", this.port);

		if (this.chnl.equals("TLS")) {
			props.put("mail.smtp.starttls.enable", "true");
		}
		else if (this.chnl.equals("SSL")) {
			props.put("mail.smtp.socketFactory.port", this.port);
			props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
		}
		else {
			props.put("mail.smtp.starttls.enable", "true");
			props.put("mail.smtp.socketFactory.port", this.port);
			props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
		}

		if (this.auth.equals("Y")) {
			props.put("mail.smtp.auth", "true");
		}
		else {
			props.put("mail.smtp.auth", "false");
		}

		MyAuthenticator auth = new MyAuthenticator(this.auid, this.aupw);

		Session msession = Session.getInstance(props, auth);
		//msession.setDebug(true);

		MimeMessage msg = new MimeMessage(msession);
		msg.setFrom(new InternetAddress(this.auid, "SSO 시스템", "utf-8"));
		msg.setSubject(subject, "utf-8");
		msg.setContent(content, "text/plain; charset=utf-8");

		Transport trns = msession.getTransport("smtp");
		trns.connect();

		for (int i = 0; i < recipient.size(); i++) {
			try {
				trns.sendMessage(msg, InternetAddress.parse(recipient.get(i)));
			}
			catch (Exception e) {
				log.debug("### send e-mail: {}: {}", recipient.get(i), e.toString());
			}
		}

		trns.close();
    }

	private void sendMail() throws Exception
	{
		if (recipient.size() == 0 || subject == null || content == null) {
			return;
		}

		if (referrer == null){
			referrer = "";
		}

		Properties props = System.getProperties();
		props.put("mail.smtp.host", this.host);
		props.put("mail.smtp.port", this.port);

		if (this.chnl.equals("TLS")) {
			props.put("mail.smtp.starttls.enable", "true");
		}
		else if (this.chnl.equals("SSL")) {
			props.put("mail.smtp.socketFactory.port", this.port);
			props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
		}
		else {
			props.put("mail.smtp.starttls.enable", "true");
			props.put("mail.smtp.socketFactory.port", this.port);
			props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
		}

		if (this.auth.equals("Y")) {
			props.put("mail.smtp.auth", "true");
		}
		else {
			props.put("mail.smtp.auth", "false");
		}

		MyAuthenticator auth = new MyAuthenticator(this.auid, this.aupw);

		Session msession = Session.getInstance(props, auth);
		//msession.setDebug(true);

		MimeMessage msg = new MimeMessage(msession);
		msg.setFrom(new InternetAddress(this.auid, "SSO 시스템", "utf-8"));
		msg.setSubject(subject, "utf-8");
		msg.setContent(content, "text/plain; charset=utf-8");

		List<String> ccList = new ArrayList<String>(Arrays.asList(referrer.split(";")));
		for (int i = 0; i < ccList.size(); i++) {
			if (!ccList.get(i).trim().equals("")) {
				int idx = recipient.indexOf(ccList.get(i).trim());
				if (idx == -1)
					recipient.add(ccList.get(i).trim());
			}
		}

		Transport trns = msession.getTransport("smtp");
		trns.connect();

		for (int i = 0; i < recipient.size(); i++) {
			try {
				trns.sendMessage(msg, InternetAddress.parse(recipient.get(i)));
			}
			catch (Exception e) {
				log.debug("### send e-mail: {}: {}", recipient.get(i), e.toString());
			}
		}

		trns.close();
    }

	class MyAuthenticator extends Authenticator
	{
		private String authId;
		private String authPw;

		MyAuthenticator(String authId, String authPw)
		{
			this.authId = authId;
			this.authPw = authPw;
		}

		protected PasswordAuthentication getPasswordAuthentication()
		{
			return new PasswordAuthentication(authId, authPw);
		}
	}
}