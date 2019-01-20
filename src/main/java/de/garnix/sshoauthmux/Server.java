package de.garnix.sshoauthmux;

import org.aeonbits.owner.ConfigFactory;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.*;
import org.apache.sshd.server.auth.AsyncAuthException;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.forward.ForwardingFilter;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.security.PublicKey;
import java.util.Random;

class Server {

	private static Logger logger = LoggerFactory.getLogger(Server.class);
	private static SshServer sshd;

	static void start(int port) throws IOException {
		sshd = SshServer.setUpDefaultServer();
		sshd.setPort(port);
		sshd.setPublickeyAuthenticator(new MyPublickeyAuthenticator());
		// TODO: Make this configurable
		sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(
//				FileSystems.getDefault().getPath(port==22 ? "/etc/sshd-oauthmux" : ".", "hostkey.ser")));
				FileSystems.getDefault().getPath("/etc/sshd-oauthmux", "hostkey.ser")));
		sshd.getSessionFactory();
		sshd.setForwardingFilter(new MyForwardingFilter());
//		sshd.setShellFactory(new ProcessShellFactory("/bin/cat"));
		sshd.setShellFactory(new PseudoShellCommand.Factory());
		sshd.setForwarderFactory(new ServletClientForwarder.Factory());
		sshd.setCommandFactory(new ControlCommand.Factory());
		sshd.start();
	}

	static void stop() {
		Random r = new Random();
		MyConfig config = ConfigFactory.create(MyConfig.class);
		int offset = config.sshReconnectOffset();
		for (SshClientConnectInfo ii : SshClientConnectInfo.getSessions()) {
			if (ii.pseudoShell !=null) {
				try {
					String reconnect = " (retry: " + (offset + r.nextInt(config.sshReconnectRandom())) + " seconds)";
					ii.pseudoShell.out.write(("Reverse Server shutting down for maintenance / software upgrade " +
					reconnect + "\r\n").getBytes());
					ii.pseudoShell.out.flush();
				} catch (Exception ioe) {};
			}
			ii.session.close(false);
		}
		try {
			Thread.sleep(9000);
			sshd.close(true);
		} catch (Exception e) {};
	}

	private static class MyPublickeyAuthenticator implements PublickeyAuthenticator {

		@Override
		public boolean authenticate(String s, PublicKey publicKey, ServerSession serverSession) throws AsyncAuthException {
			SshClientConnectInfo meta = new SshClientConnectInfo();
			meta.clientKey = publicKey;
			meta.socketAddress = serverSession.getClientAddress();
			meta.session = serverSession;
			logger.info("Authenticated Session: " + serverSession.getClientAddress() + " with goodKey " +
					Integer.toHexString(Database.goodHashCode(meta.clientKey)) + " / badKey " +
					Integer.toHexString(Database.badHashCode(meta.clientKey)));
			SshClientConnectInfo.putSession(meta, false);
			return true;
		}
	}

	private static class MyForwardingFilter implements ForwardingFilter {

		@Override
		public boolean canForwardX11(Session session, String requestType) {
			System.out.println ("canForwardX11?");
			return false;
		}

		@Override
		public boolean canForwardAgent(Session session, String requestType) {
			System.out.println ("canForwardAgent?");
			return false;
		}

		@Override
		public boolean canListen(SshdSocketAddress address, Session session) {
			logger.info ("canListen? host=" + address.getHostName() + " toAddress=" + address.toInetSocketAddress());
			System.out.println (byteDumper(session.getSessionId()));
			return true;
		}

		@Override
		public boolean canConnect(Type type, SshdSocketAddress address, Session session) {
			System.out.println ("canConnect?");
			return false;
		}
	}

	private static String byteDumper(byte[] b) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < sb.length(); i++)
			sb.append(Integer.toHexString(b[i])).append(':');
		sb.append(" (length=").append(sb.length()).append(")");
		return sb.toString();
	}
}
