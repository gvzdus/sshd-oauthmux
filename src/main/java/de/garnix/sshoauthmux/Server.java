package de.garnix.sshoauthmux;

import org.aeonbits.owner.ConfigFactory;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelListener;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
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

public class Server {

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

	public static void main(String [] args) throws Exception {

		// TODO: Make this configurable
		start(22022);

		for (int i = 0; i < 2; i++) {
			Thread.sleep(10000);
			SshClientConnectInfo sessions[] = SshClientConnectInfo.getSessions();
			SshClientConnectInfo info = sessions.length>0 ? sessions[0] : null;
			if (info != null) {
				info.pseudoShell.out.write("Hello world".getBytes());
				info.pseudoShell.out.flush();
				//	if (0 == 0) continue;

				ServletClientChannel channel = new ServletClientChannel(new SshdSocketAddress("weitweg.vodafone.de", 1234), info);
				Session session = info.session;
				// session.setAttribute(ServletClientChannel.class, channel);

				final ConnectionService service = info.forwarder.getConnectionService();

				service.registerChannel(channel);
				channel.open().addListener(future -> {
					Throwable t = future.getException();
					if (t != null) {
						logger.warn("Failed ({}) to open channel for session={}: {}",
								t.getClass().getSimpleName(), session.toString(), t.getMessage());
						logger.debug("sessionCreated(" + session + ") channel=" + channel + " open failure details", t);
						service.unregisterChannel(channel);
						channel.close(false);
					}
				});
				byte[] b = "GET / HTTP/1.0\r\nHost: 2scale.net\r\n\r\n".getBytes();
				Buffer buffer = new ByteArrayBuffer(b);
				info.forwarder.messageReceived(info, channel, buffer);
				channel.addChannelListener(new ChannelListener() {
					@Override
					public void channelStateChanged(Channel genericChannel, String hint) {
						if ("SSH_MSG_CHANNEL_EOF".equals(hint))
							try {
								channel.close(false);
							} catch (Exception e) {
								e.printStackTrace();
							}
					}
				});
//				channel.handleRequest(buffer);
//				channel.writePacket(buffer);
			}
		}
		Thread.sleep(5000);
		for (SshClientConnectInfo ii : SshClientConnectInfo.getSessions()) {
			if (ii.pseudoShell !=null) {
				ii.pseudoShell.out.write("Reverse Server shutting down for maintenance / software upgrade\n".getBytes());
				ii.pseudoShell.out.flush();
			}
			ii.session.close(false);
		}
		Thread.sleep(15000);
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
			return false;
		}

		@Override
		public boolean canForwardAgent(Session session, String requestType) {
			return false;
		}

		@Override
		public boolean canListen(SshdSocketAddress address, Session session) {
			return true;
		}

		@Override
		public boolean canConnect(Type type, SshdSocketAddress address, Session session) {
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
