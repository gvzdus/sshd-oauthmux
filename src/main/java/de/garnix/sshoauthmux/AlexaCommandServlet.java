package de.garnix.sshoauthmux;

import org.aeonbits.owner.ConfigFactory;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.util.Enumeration;
import java.util.Map;

public class AlexaCommandServlet extends HttpServlet {

	private static final Logger logger = LoggerFactory.getLogger(AlexaCommandServlet.class);
	private static final MyConfig config = ConfigFactory.create(MyConfig.class);

	@Override
	public void service (HttpServletRequest request, HttpServletResponse response) throws IOException {

		String neededSecret = config.lambdaInClientAuthorization();
		if (neededSecret!=null && neededSecret.length()>0 && (! neededSecret.equals(request.getHeader("X-LambdaSecret")))) {
			logger.warn("AlexaCmd call with missing or wrong security header");
			for (Map.Entry<String,String[]> me : request.getParameterMap().entrySet()) {
				logger.info ("Parameter " + me.getKey() + " is " + me.getValue()[0]);
			}
			logger.info ("X-LambdaSecret: " + request.getHeader("X-LambdaSecret"));
			response.setStatus(404);
			return;
		}

		long start = System.currentTimeMillis();
		if (logger.isDebugEnabled()) {
			Enumeration<String> e = request.getHeaderNames();
			while (e.hasMoreElements()) {
				String hn = e.nextElement();
				logger.debug("Header " + hn + ": " + request.getHeader(hn));
			}
		}

		Integer uid = getClientInfo(request);
		if (uid==null) {
			logger.info ("Rejected request with unknown token Auth header " + request.getHeader("Authorization"));
			response.setStatus(401);
			return;
		}
		SshClientConnectInfo info = SshClientConnectInfo.getBySession(uid);
		if (info==null) {
			logger.info ("Session for authenticated UID " + Integer.toHexString(uid) + " not found");
			response.setStatus(404);
			return;
		}
		if (info.getUid()==null || info.getUid().intValue()!=uid) {
			logger.info ("Session for authenticated UID " + Integer.toHexString(uid) + " found, but not validated");
			response.setStatus(404);
			return;
		}

		try {
			triggerRequest(info, request, response, start);
		} catch (Exception e) {
			logger.warn ("Exception raised: " + e.getMessage(), e);
		}
	}

	private static String getLine(ByteArrayBuffer bb) {
		StringBuilder sb = new StringBuilder();
		while (bb.available()>0) {
			char c = (char) (bb.getByte() & 0xff);
			if (c == '\r') continue;
			if (c == '\n') break;
			sb.append(c);
		}
		return sb.toString();
	}

	private static void triggerRequest(SshClientConnectInfo info, HttpServletRequest request, HttpServletResponse response, long start) throws Exception {
		String path = "/";

		StringBuilder sb = new StringBuilder(request.getMethod() + " ");
		sb.append(path).append(" HTTP/1.1\r\n");
		sb.append("Host: localhost\r\n");
		sb.append("Connection: close\r\n");
		Enumeration<String> hnEnum = request.getHeaderNames();
		while (hnEnum.hasMoreElements()) {
			String hn = hnEnum.nextElement();
			String hnv = request.getHeader(hn);
			if (hn.equals("User-Agent") || hn.equals("Accept") || hn.equals("Lang") || hn.equals("Content-Type"))
				sb.append(hn).append(": ").append(hnv).append("\r\n");
		}

		byte[] body = null;
		if (request.getMethod().equalsIgnoreCase("POST")) {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			InputStream is = request.getInputStream();
			byte buf[] = new byte[32768];
			int read;
			while ((read = is.read(buf))>0)
				baos.write(buf, 0, read);
			body = baos.toByteArray();
			sb.append("Content-Length: ").append(body.length).append("\r\n");
		}
		sb.append("\r\n");

		Session session = info.session;
		ServletClientChannel channel;
		if (logger.isDebugEnabled())
			logger.debug ("info.activeChannel=" + info.freeChannel);
		synchronized (info) {
			if (info.freeChannel != null && !(info.freeChannel.isClosing() || info.freeChannel.isClosed())) {
				channel = info.freeChannel;
				info.freeChannel = null; // it is in use now
			} else
				channel = ServletClientChannel.openNewChannel(info);
		}
		byte[] b1;
		if (body == null) {
			b1 = sb.toString().getBytes();
		} else {
			b1 = sb.toString().getBytes();
			b1 = ByteBuffer.allocate(b1.length + body.length).put(b1).put(body).array();
		}

		Buffer buffer = new ByteArrayBuffer(b1);
		PipedInputStream pi = new PipedInputStream(102400);
		channel.setPipedInputStream(pi);
		info.forwarder.messageReceived(info, channel, buffer);


		byte[] buf = new byte[16384];
		int avail;
		Long cl = null;
		avail = pi.read(buf);
		ByteArrayBuffer bb = new ByteArrayBuffer(buf);

		if (bb.available()==0 || avail<=0) {
			response.setStatus(500);
			response.getWriter().print("No bytes received - server unreachable");
			return;
		}
		OutputStream po = response.getOutputStream();
		String ln = getLine(bb);
		if (! ln.startsWith("HTTP/"))
			throw new IOException("Response does not start with HTTP/xx, but " + ln);
		int i = ln.indexOf(' ');
		if (i < 0)
			throw new IOException("Invalid HTTP status line");
		int status = Integer.parseInt(ln.substring(i+1, i+4));
		response.setStatus(status);
		String procTime = "";
		do {
			ln = getLine(bb);
			if (ln.length()==0) break;
			if (! ln.startsWith(" ")) {
				i = ln.indexOf(':');
				String hn = ln.substring(0, i);
				String hnl = hn.toLowerCase();
				ln = ln.substring(i+1).trim();
				switch (hnl) {
					case "date":
					case "server":
					case "last-modified":
					case "content-type":
						response.setHeader(hn, ln);
						break;
					case "x-proctime":
						procTime = ln;
						break;
					case "content-length":
						cl = Long.parseLong(ln);
						break;
				}
			}
		} while (true);
		response.setHeader("X-ProcTime", procTime + " sshdprx:" + (System.currentTimeMillis()-start));

		if (cl==null) {
			po.write(buf, bb.rpos(), avail - bb.rpos());
			while ((avail = pi.read(buf)) > 0) {
				po.write(buf, 0, avail);
			}
		} else {
			if (logger.isDebugEnabled())
				logger.debug ("CL=" + cl + ", blen=" + (avail-bb.rpos()));
			po.write(buf, bb.rpos(), avail - bb.rpos());
			cl -= avail - bb.rpos();
			while (cl > 0) {
				avail = pi.read(buf);
				if (avail<=0) break;
				po.write(buf, 0, avail);
				cl -= avail;
			}
		}
		pi.close();

		info.freeChannel = ServletClientChannel.openNewChannel(info);
	}

	/**
	 *
	 * @param req Incoming request from Lambda function
	 * @return Integer with clientID based on first section
	 */

	private static Integer getClientInfo(HttpServletRequest req) {
		String s = req.getHeader("Authorization");
		if (s==null || !s.startsWith("Bearer ")) return null;
		s = s.substring(7).trim();
		int idx = s.indexOf('-');
		if (idx>=0)
			s = s.substring(idx+1);
		try {
			long bearerToken = Long.parseUnsignedLong(s, 16);
			Integer hc = Database.validateBearerToken(bearerToken);
			if (hc==null) {
				if (logger.isDebugEnabled())
					logger.debug("BearerToken '" + s + "' did not resolve as proxy-token");
				hc = Integer.parseUnsignedInt(s, 16);
				return hc;
			}
			if (logger.isDebugEnabled())
				logger.debug ("BearerToken '" + s + "' is HC=" + Integer.toHexString(hc));
			return hc;
		} catch (Exception e) {
			logger.info ("Cannot parse Bearer " + s);
		}
		return null;
	}
}
