package de.garnix.sshoauthmux;

import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelPipedInputStream;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.SocketAddress;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;


public class SshClientConnectInfo {
	PublicKey clientKey;
	public SocketAddress socketAddress;
	public ServerSession session;
	public String serverLocalEndpoint;
	public int serverLocalPort;
	ServletClientForwarder forwarder;
	PseudoShellCommand pseudoShell;
	ServletClientChannel freeChannel;
	Integer uid;
	private static final Logger logger = LoggerFactory.getLogger(SshClientConnectInfo.class);

	// public int getClientKeyHC() {
	//	return clientKey.hashCode();
	//}
	public Integer getUid() {
		return uid;
	}

	public void setUid(int uid) {
		this.uid = uid;
	}

	private static Map<Object, SshClientConnectInfo> activeMap = new HashMap<>();

	static SshClientConnectInfo getBySession (Session session) {
		if (session != null)
			synchronized (activeMap) {
				return activeMap.get(session);
			}
		return null;
	}

	static SshClientConnectInfo getBySession (int uid) {
		synchronized (activeMap) {
			SshClientConnectInfo i = activeMap.get(uid);
			if (i!=null && i.session!=null) {
				if (!i.session.isClosing())
					return i;
				else {
					activeMap.remove(i.session);
					activeMap.remove(uid);
				}
			}
		}
		return null;
	}

	public ServletClientForwarder forwarder() {
		return forwarder;
	}

	public static SshClientConnectInfo[] getSessions() {
		LinkedList<SshClientConnectInfo> list = new LinkedList<>();
		synchronized (activeMap) {
			for (Map.Entry<Object,SshClientConnectInfo> me : activeMap.entrySet())
				if (me.getKey() instanceof Session)
					list.add(me.getValue());
		}
		return list.toArray(new SshClientConnectInfo[list.size()]);
	}

	public static void closeEofSessions() {
		LinkedList<SshClientConnectInfo> list = new LinkedList<>();
		try {
			synchronized (activeMap) {
				for (Map.Entry<Object, SshClientConnectInfo> me : activeMap.entrySet())
					if (me.getKey() instanceof Session) {
						SshClientConnectInfo i = me.getValue();
						if (i.pseudoShell != null && i.pseudoShell.in instanceof ChannelPipedInputStream) {
							ChannelPipedInputStream cpis = (ChannelPipedInputStream) i.pseudoShell.in;
							if (logger.isDebugEnabled()) {
								logger.debug("cpis isOpen: " + cpis.isOpen() + " avail: " + cpis.available());
							}
							int avail = cpis.available();
							if (avail<0) {
								// EOF received
								list.add(i);
							} else if (avail>0) {
								int c = cpis.read();
								if (logger.isDebugEnabled())
									logger.debug("Read " + Integer.toHexString(c) + " from SSH");
								if (c==0x03 || c==0x04) {
									// Ctrl-C, Ctrl-D
									list.add(i);
								}
							}
						}
					}
			}
		} catch (Exception e) {
			logger.warn("Got exception " + e, e);
		}
		for (SshClientConnectInfo i : list) {
			if (i.session!=null) {
				logger.info ("Closing session " + Integer.toHexString(i.getUid()!=null ? i.getUid() : 0) + ", " +
						i.session.toString() + " by client-EOF" );
				i.session.close(true);
			}
		}
	}

	/*
	public void registerPublicKeyHashCode() {
		synchronized (activeMap) {
			activeMap.put(getClientKeyHC(), this);
		}
	}
	*/

	public String toString() {
		return " clientKey=" + clientKey + ", sockAddr=" + socketAddress + ", session=" + session;
	}

	/*
		Store the Info by session.
		If removeByKey is set, then the hashCode of the public key is also
		overwritten, if a session already exists and is alive.
	 */
	static void putSession(SshClientConnectInfo meta, boolean removeByKey) {
		synchronized (activeMap) {
			activeMap.put(meta.session, meta);
			Integer uid = meta.getUid();
			SshClientConnectInfo info = uid!=null ? activeMap.get(uid) : null;
			if (info!=null) {
				if (info != meta && (info.session.isClosing() || removeByKey)) {
					info.session.close(true);
					activeMap.put(uid, meta);
				}
			} else {
				if (uid!=null)
					activeMap.put(uid, meta);
			}
		}
	}

	static void removeSession(Session session) {
		synchronized (activeMap) {
			SshClientConnectInfo i = activeMap.remove(session);
			if (i!=null && i.uid!=null) {
				SshClientConnectInfo old = activeMap.get(i.uid);
				if (old!=null && old.session==session)
					activeMap.remove(i.uid);
			}
		}
	}


}
