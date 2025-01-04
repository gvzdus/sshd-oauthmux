package de.garnix.sshoauthmux;

import org.apache.sshd.common.session.Session;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.SessionAware;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.shell.ShellFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

class PseudoShellCommand implements Command, SessionAware {
	InputStream in;
	OutputStream out;
	private OutputStream err;
	private ExitCallback exitCallback;
	private Session session;

	private static final Logger log = LoggerFactory.getLogger(PseudoShellCommand.class);

	private PseudoShellCommand(Session session, String s) {
		this.session = session;
		if (log.isDebugEnabled())
			log.debug("New PseudoShellCommand called with " + s);
	}

	@Override
	public void start(ChannelSession cs, Environment env) throws IOException {
		SshClientConnectInfo info = SshClientConnectInfo.getBySession(session);
		int id = Database.searchClientCert(info.clientKey);
		if (id==0) {
			log.info ("Public Key not known - terminating session");
			out.write("Your public key is not known, please register first. (retry: 3600 seconds)\r\n".getBytes());
			out.flush();
			session.close(false);
			return;
		} else {
			info.setUid(id);
			log.info ("Identified SSH session of " + Integer.toHexString(id));
			SshClientConnectInfo old = SshClientConnectInfo.getBySession(id);
			out.write(("Welcome at the reverse proxy!\r\n" +
					"This pseudoshell does not react to any input - do not get irritated.\r\n").getBytes());
			out.flush();
			if (log.isDebugEnabled())
				log.debug("old=" + (old!=null ? old.session : null) + " this=" + session);
			if (old!=null && old.session!=session && !old.session.isClosed()) {
				log.info("Killing old session " + old.session);
				/*  DID NOT WORK FINE
				if (old.pseudoShell!=null && old.pseudoShell.out!=null) {
					old.pseudoShell.out.write("There is another, newer session with your key, terminating yours (retry: 600 seconds)\r\n".getBytes());
				}
				old.session.close(false);
				*/
				old.session.close(true);
				SshClientConnectInfo.removeSession(old.session);
			}
			SshClientConnectInfo.putSession(info, true);
		}
		if (log.isDebugEnabled())
			log.debug("PseudoShell started on " + session);
		/*
		env.addSignalListener(signal ->
				log.info ("SIGNAL received: " + signal.getNumeric() + " = " + signal.toString()));

		 */
		if (log.isTraceEnabled())
			for (Map.Entry<String,String> me : env.getEnv().entrySet()) {
				log.trace ("ENV: " + me.getKey() + "=" + me.getValue());
			}
	}

	@Override
	public void destroy(ChannelSession cs) throws Exception {
		if (log.isDebugEnabled())
			log.debug("PseudoShell destroyed on " + session);
		SshClientConnectInfo.removeSession(cs.getSession());
		if (exitCallback!=null)
			exitCallback.onExit(0, "Never lived");
	}

	@Override
	public void setInputStream(InputStream in) {
		this.in = in;
		if (log.isDebugEnabled())
			log.info ("PseudoShell InputStream is " + in.getClass().getCanonicalName());
	}

	@Override
	public void setOutputStream(OutputStream out) {
		this.out = out;
		if (log.isDebugEnabled())
			log.info ("PseudoShell OutputStream is " + out.getClass().getCanonicalName());
	}

	@Override
	public void setErrorStream(OutputStream err) {
		this.err = err;

	}

	@Override
	public void setExitCallback(ExitCallback callback) {
		this.exitCallback = callback;
	}

	@Override
	public void setSession(ServerSession session) {
		this.session = session;
		SshClientConnectInfo info = SshClientConnectInfo.getBySession(session);
		if (info!=null)
			info.pseudoShell = this;
	}


	public static class Factory implements ShellFactory {
		@Override
		public Command createShell(ChannelSession cs) {
			return new PseudoShellCommand (cs.getSession(), "CREATE");
		}
	}
}
