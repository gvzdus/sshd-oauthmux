package de.garnix.sshoauthmux;

import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.forward.ForwardingFilterFactory;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.forward.TcpForwardingFilter;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

import java.io.IOException;
import java.util.Objects;
import java.util.function.Consumer;

import static de.garnix.sshoauthmux.SshClientConnectInfo.putSession;


class ServletClientForwarder extends org.apache.sshd.common.forward.DefaultForwardingFilter {

	private static Logger log = LoggerFactory.getLogger(ServletClientForwarder.class);

	private ServletClientForwarder(ConnectionService service) {
		super(service);
		Session session = getSession();
		log.info("MyForwarded initializing on " + session);

		SshClientConnectInfo omi = SshClientConnectInfo.getBySession(session);
		if (omi != null)
			omi.forwarder = this;
		else
			log.warn("On init, did not find my session " + session + " in table");
	}

	@Override
	public synchronized SshdSocketAddress localPortForwardingRequested(SshdSocketAddress local) throws IOException {
		Objects.requireNonNull(local, "Local address is null");
		ValidateUtils.checkTrue(local.getPort() >= 0, "Invalid local port: %s", local);

		Session session = getSession();

		boolean found = false;
		SshClientConnectInfo omi = SshClientConnectInfo.getBySession(session);
		if (omi != null) {
			found = true;
			omi.serverLocalEndpoint = local.getHostName();
			omi.serverLocalPort = local.getPort();
			omi.forwarder = this;
			if (log.isDebugEnabled())
				log.debug ("On localPortForwardingRequested, registered handler in session " + session.hashCode());
			putSession(omi, true);
		} else {
			log.warn ("On localPortForwardingRequested, did not find the session " + session);
		}
		log.debug("localPortForwardingRequested entry, sessionFound=" + found);

		FactoryManager manager = Objects.requireNonNull(session.getFactoryManager(), "No factory manager");
		TcpForwardingFilter filter = manager.getTcpForwardingFilter();
		try {
			if ((filter == null) || (!filter.canListen(local, session))) {
				if (log.isDebugEnabled()) {
					log.debug("localPortForwardingRequested(" + session + ")[" + local + "][haveFilter=" + (filter != null) + "] rejected");
				}
				return null;
			}
		} catch (Error e) {
			log.warn("localPortForwardingRequested({})[{}] failed ({}) to consult forwarding filter: {}",
					session, local, e.getClass().getSimpleName(), e.getMessage());
			if (log.isDebugEnabled()) {
				log.debug("localPortForwardingRequested(" + this + ")[" + local + "] filter consultation failure details", e);
			}
			throw new RuntimeSshException(e);
		}

		signalEstablishingExplicitTunnel(local, null, true);
		SshdSocketAddress result;
		try {
			//InetSocketAddress bound = doBind(local, staticIoHandlerFactory);
			result = new SshdSocketAddress(local.getHostName(), local.getPort());
			if (log.isDebugEnabled()) {
				log.debug("localPortForwardingRequested(" + local + "): " + result);
			}

		} catch (RuntimeException e) {
			try {
				localPortForwardingCancelled(local);
			} catch (IOException | RuntimeException err) {
				e.addSuppressed(e);
			}
			signalEstablishedExplicitTunnel(local, null, true, null, e);
			throw e;
		}

		signalEstablishedExplicitTunnel(local, null, true, result, null);
		log.debug("localPortForwardingRequested exit");

		return result;
	}

	void messageReceived(SshClientConnectInfo info, ServletClientChannel channel, Readable message) throws Exception {
		//TcpipClientChannel channel = (TcpipClientChannel) session.getAttribute(TcpipClientChannel.class);
		long totalMessages = 1;
		Buffer buffer = new ByteArrayBuffer(message.available() + Long.SIZE, false);
		buffer.putBuffer(message);

		if (log.isTraceEnabled()) {
			log.trace("messageReceived({}) channel={}, count={}, handle len={}",
					info.session, channel, totalMessages, message.available());
		}

		OpenFuture future = channel.getOpenFuture();
		Consumer<Throwable> errHandler = future.isOpened() ? null : e -> {
			try {
				log.warn("messageReceived({}) failed ({}) to signal {}[{}] on channel={}: {}",
						info.session, e.getClass().getSimpleName(), e.getClass().getSimpleName(),
						e.getMessage(), channel, e.getMessage());
//					channel.getexceptionCaught(info.session, e);
			} catch (Exception err) {
				log.warn("messageReceived({}) failed ({}) to signal {}[{}] on channel={}: {}",
						info.session, err.getClass().getSimpleName(), e.getClass().getSimpleName(),
						e.getMessage(), channel, err.getMessage());
			}
		};
		ClientChannelPendingMessagesQueue messagesQueue = channel.getPendingMessagesQueue();
		int pendCount = messagesQueue.handleIncomingMessage(buffer, errHandler);
		if (log.isTraceEnabled()) {
			log.trace("messageReceived({}) channel={} pend count={} after processing message",
					info.session, channel, pendCount);
		}
	}


	@Override
	public void close() throws IOException {
		super.close();
		log.info("MyForwarder CLOSE called");
	}

	public static class Factory implements ForwardingFilterFactory {

		@Override
		public org.apache.sshd.common.forward.ForwardingFilter create(ConnectionService service) {
			return new ServletClientForwarder(service);
		}

	}
}