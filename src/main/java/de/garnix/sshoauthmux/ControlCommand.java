package de.garnix.sshoauthmux;

import org.apache.sshd.common.session.Session;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.SessionAware;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.command.CommandFactory;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


class ControlCommand implements Command, SessionAware {

	private static final Logger log = LoggerFactory.getLogger(ControlCommand.class);

	private final String cmd;
	private ExitCallback onExit = null;
	private OutputStream os;
	//private OutputStream err;
	private Session session;
	private SshClientConnectInfo info;

	private ControlCommand(String s) {
		this.cmd = s;
	}

	@Override
	public void setInputStream(InputStream inputStream) {

	}

	@Override
	public void setOutputStream(OutputStream outputStream) {
		os = outputStream;
	}

	@Override
	public void setErrorStream(OutputStream outputStream) {
		//err = outputStream;
	}

	@Override
	public void setExitCallback(ExitCallback exitCallback) {
		onExit = exitCallback;
	}

	private static final Pattern email_pattern = Pattern.compile(".*\\s+email=([^ ]+)( .*|$)", Pattern.CASE_INSENSITIVE);
	private static final Pattern path_pattern = Pattern.compile(".*\\s+path=([^ ]+)( .*|$)", Pattern.CASE_INSENSITIVE);
	private static final Pattern keyhash_pattern = Pattern.compile(".*\\s+keyhash=([A-Fa-f0-9]+)( .*|$)", Pattern.CASE_INSENSITIVE);

	@Override
	public void start(ChannelSession cs, Environment environment) throws IOException {
		StringBuilder sbErr = new StringBuilder();
		StringBuilder sbOut = new StringBuilder();
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
		sdf.setTimeZone(TimeZone.getTimeZone("GMT"));

		if (log.isDebugEnabled()) {
			log.debug ("Start of executing CMD " + cmd + " with " +
					Integer.toHexString(info!=null ? info.clientKey.hashCode() : 0));
		}
		try {
			if (info != null) {
				if (cmd.startsWith("register")) {
					Matcher m;
					m = email_pattern.matcher(cmd);
					String email = (m.matches()) ? m.group(1) : null;
					m = path_pattern.matcher(cmd);
					String path = (m.matches()) ? m.group(1) : "/";
					m = keyhash_pattern.matcher(cmd);
					String keyhash = (m.matches() ? m.group(1) : null);
					String id = Database.insertClientCert(info.clientKey, email, path, keyhash);
					sbOut.append("Registered. Your key to activate the FHEMlazy skill with Alexa etc. is:\r\n\r\n\r\n     ");
					sbOut.append(id).append("\r\n\r\n");
					sbOut.append("Note it down NOW!\r\n");
					sbOut.append("There is no way to get it again apart from registrating yourself again!\r\n");
					sbOut.append("\r\n");
					sbOut.append("Your are now set up to create the reverse-tunnel to your computer with\r\n\r\n");
					sbOut.append("ssh -p 58824 -R 1234:localhost:3000 fhem-va.fhem.de\r\n\r\n");
					sbOut.append("(assuming that alexa-fhem is running on localhost:3000)\r\n");

					return;
				}
				if (cmd.startsWith("status")) {
					Database.UserInfo ui = Database.getUserInfo(info.clientKey);
					if (ui==null) {
						sbOut.append("Unregistered.\r\nYour SSH key ist not registered.\r\n");
					} else {
						sbOut.append("Registered.\r\n");
						sbOut.append("Registered on ").append(sdf.format(ui.getCreated())).append(" as ").append(
								ui.getKeyId().toUpperCase()).append(".\r\n");
					}
					return;
				}
				if (cmd.startsWith("unregister")) {
					if (Database.removeClientCert(info.clientKey)==0) {
						sbOut.append("Your public key was not found\r\n");
					} else {
						sbOut.append("Your registration has been removed\r\n");
					}
					return;
				}
				sbErr.append("Invalid command ").append(cmd).append(" received, valid commands are register, status and unregister\r\n");
			} else
				sbErr.append("No session found");
		} finally {
			try {
				log.info("Request " + cmd + " from " + session + " answered with out=" +
						sbOut.toString().replaceAll("\r\n", "\\\\n").replaceAll("[0-9A-F]{6}", "XXXXXX") + ", err=" + sbErr.toString());
				if (sbErr.length()>0)
					os.write(sbErr.toString().getBytes());
				if (sbOut.length()>0)
					os.write(sbOut.toString().getBytes());
				onExit.onExit(0, "Goodbye");
				SshClientConnectInfo.removeSession(session);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	@Override
	public void destroy(ChannelSession cs) throws Exception {
	}

	@Override
	public void setSession(ServerSession session) {
		this.session = session;
		this.info = SshClientConnectInfo.getBySession(session);
	}

	static class Factory implements CommandFactory {
		@Override
		public Command createCommand(ChannelSession channelSession, String command) throws IOException {
			return new ControlCommand(command);
		}
	}
}
