package de.garnix.sshoauthmux;

import org.apache.sshd.client.channel.AbstractClientChannel;
import org.apache.sshd.client.channel.ClientChannelPendingMessagesQueue;
import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.channel.Window;
import org.apache.sshd.common.forward.ForwardingTunnelEndpointsProvider;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

class ServletClientChannel extends AbstractClientChannel implements ForwardingTunnelEndpointsProvider {
	private final ClientChannelPendingMessagesQueue messagesQueue;
	private SshdSocketAddress tunnelEntrance;
	private SshdSocketAddress tunnelExit;
	private PipedOutputStream pipedOutputStream;
	//private SshClientConnectInfo info;

	private static final String TYPESTR = "forwarded-tcpip";
	private static Logger log = LoggerFactory.getLogger(ServletClientChannel.class);

	ServletClientChannel(PipedInputStream pi, SshdSocketAddress remote, SshClientConnectInfo info) throws IOException {
		super(TYPESTR);
		this.tunnelEntrance = remote;
		this.tunnelExit = new SshdSocketAddress(info.serverLocalEndpoint, info.serverLocalPort);
		this.pipedOutputStream = new PipedOutputStream(pi);
		this.messagesQueue = new ClientChannelPendingMessagesQueue(this);
	}

	OpenFuture getOpenFuture() {
		return openFuture;
	}

	/*
	public TcpipClientChannel.Type getTcpipChannelType() {
		return TcpipClientChannel.Type.Forwarded;
	}
	*/

	ClientChannelPendingMessagesQueue getPendingMessagesQueue() {
		return messagesQueue;
	}

	@Override
	public synchronized OpenFuture open() throws IOException {
		if (closeFuture.isClosed()) {
			throw new SshException("Session has been closed");
		}

		// make sure the pending messages queue is 1st in line

		// GVZ: Was src
		openFuture = new DefaultOpenFuture(tunnelEntrance.getHostName(), lock)
				.addListener(getPendingMessagesQueue());
		if (log.isDebugEnabled()) {
			log.debug("open({}) send SSH_MSG_CHANNEL_OPEN", this);
		}

		Session session = getSession();
		// String dstHost = dstAddress.getHostAddress();
		String dstHost = tunnelExit.getHostName();
		String srcHost = tunnelEntrance.getHostName();
		Window wLocal = getLocalWindow();
		String type = getChannelType();
		Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_OPEN,
				type.length() + srcHost.length() + dstHost.length() + Long.SIZE);
		buffer.putString(type);
		buffer.putInt(getId());
		buffer.putInt(wLocal.getSize());
		buffer.putInt(wLocal.getPacketSize());
		buffer.putString(dstHost);
		buffer.putInt(tunnelExit.getPort());
		buffer.putString(srcHost);
		buffer.putInt(tunnelEntrance.getPort());
		writePacket(buffer);
		return openFuture;
	}

	@Override
	protected Closeable getInnerCloseable() {
//		log.info("getInnerCloseable CALLED");
		try {
			pipedOutputStream.close();
		} catch (IOException e) {
			log.warn("Exception on getInnerClosable");
		}
		return super.getInnerCloseable();
/*
        return builder()
            .sequential(serverSession, super.getInnerCloseable())
            .build();
		*/
	}

	@Override
	protected void preClose() {
		IOException err = IoUtils.closeQuietly(getPendingMessagesQueue());
		if (err != null) {
			if (log.isDebugEnabled()) {
				log.debug("preClose({}) Failed ({}) to close pending messages queue: {}",
						this, err.getClass().getSimpleName(), err.getMessage());
			}
			if (log.isTraceEnabled()) {
				log.trace("preClose(" + this + ") pending messages queue close failure details", err);
			}
		}

		super.preClose();
	}

	@Override
	public SshdSocketAddress getTunnelEntrance() {
		return tunnelEntrance;
	}

	@Override
	public SshdSocketAddress getTunnelExit() {
		return tunnelExit;
	}

	@Override
	protected void doOpen() throws IOException {
		out = new ChannelOutputStream(this, getRemoteWindow(), log, SshConstants.SSH_MSG_CHANNEL_DATA, true);
		invertedIn = out;
	}

	@Override
	protected synchronized void doWriteData(byte[] data, int off, long len) throws IOException {
		ValidateUtils.checkTrue(len <= Integer.MAX_VALUE, "Data length exceeds int boundaries: %d", len);
		// Make sure we copy the data as the incoming buffer may be reused
		Buffer buf = ByteArrayBuffer.getCompactClone(data, off, (int) len);
		Window wLocal = getLocalWindow();
		wLocal.consumeAndCheck(len);
		pipedOutputStream.write(buf.array());
//		System.out.println (">>>>>>>>>>>>>>>>>>>\n" + new String(buf.array()));
	}
}
