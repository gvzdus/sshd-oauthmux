package de.garnix.sshoauthmux;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelListener;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PipedInputStream;
import java.util.HashMap;
import java.util.Map;

public class RegistrationApiServlet extends HttpServlet {

	private static final ObjectMapper mapper = new ObjectMapper();
	private static Logger logger = LoggerFactory.getLogger(RegistrationApiServlet.class);

	private static Map<String,String> NO_SESSION_FOUND_STATUS = new HashMap<>(1);
	static {
		NO_SESSION_FOUND_STATUS.put("status", "session not found");
	}

	@Override
	@SuppressWarnings("unchecked")
	public void service (HttpServletRequest request, HttpServletResponse response) throws IOException {
		HttpSession session = request.getSession();
		Map<String,String> pmap = (Map<String, String>) session.getAttribute("pmap");
		String pathInfo = request.getPathInfo();
		response.setContentType("application/json");
		Map<String, Object> rootResponse = new HashMap<>(2);
		String id = (pmap!=null) ? pmap.get("authkey") : null;
		String bearerToken = (pmap!=null) ? pmap.get("bearerToken") : null;
		Database.UserInfo ui = id!=null ? Database.getUserInfo(id) : null;

		if (pmap != null)
			rootResponse.put("params", pmap);

		if ("/params".equals(pathInfo)) {
			// Dump only parameters
		} else if ("/checkssh".equals(pathInfo)) {
			// Check online status
			if (ui!=null)
				rootResponse.put ("userstatus", ui);
		} else if ("/checknodejs".equals(pathInfo)) {
			if (ui!=null) {
				rootResponse.put("userstatus", ui);
				SshClientConnectInfo info = SshClientConnectInfo.getBySession(ui.keyId);
				if (info!=null) {
					rootResponse.put("nodejs", testServer(info, request, id));
				} else {
					rootResponse.put("nodejs", NO_SESSION_FOUND_STATUS);
				}
			}
		} else if ("/passcode".equals(pathInfo)) {
			String url = pmap.get("redirect_uri");
			// TODO: Make this configurable
			if ( url!=null &&
					! url.startsWith("https://layla.amazon.com/api/skill/link/") &&
					! url.startsWith("https://pitangui.amazon.com/api/skill/link/") &&
					! url.startsWith("https://alexa.amazon.co.jp/api/skill/link/")) {
				logger.warn("Deleting destination URL " + url + ", is not one of the loved once...");
				url = null;
			}

			if (ui!=null) {
				String atoken;
				if (bearerToken==null) {
					atoken = ui.generateAccessToken(true);
				} else {
					atoken = ui.generateAccessToken(false);
					OAuthTokenServlet.setCode(atoken, ui.keyId, bearerToken);
				}
				if (url!=null) {
					url = url + (url.indexOf('?') >= 0 ? "&" : "?") + "state=" + pmap.get("state");
					url = url + "&code=" + atoken;
					response.sendRedirect(url);
					session.invalidate();
				}
			}
		} else {
			response.setStatus(404);
		}
		mapper.writeValue(response.getOutputStream(), rootResponse);

	}

	private static Map testServer(SshClientConnectInfo info, HttpServletRequest request, String key)  {
		Session session = info.session;
		HashMap<String,Object> result = new HashMap<>(2);
		String status = "ok";
		String [] keySplit = key!=null ? key.split("-") : new String[0];

		try {
			final ConnectionService service = info.forwarder().getConnectionService();
			ServletClientChannel channel = ServletClientChannel.openNewChannel(info);

			String bearerToken = keySplit.length==3 ? keySplit[0] + '-' + keySplit[2] : "none";
			String postBody =
					"{\"directive\":{" +
							"\"header\":"+
							"{\"namespace\":\"Alexa.Discovery\","+
							"\"name\":\"Discover\",\"payloadVersion\":\"3\","+"" +
							"\"messageId\":\"0815\"},"+
							"\"payload\":"+
							"{\"scope\":"+"" +
							"			{\"type\":\"BearerToken\","+
							"\"token\":\"" + bearerToken + "\"}}}}";
			String postHeader =
					"POST /status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n" +
							"Content-Type: application/json\r\n" +
							"Content-Length: " + postBody.length() + "\r\n\r\n";
			byte[] b = (postHeader + postBody).getBytes();

			Buffer buffer = new ByteArrayBuffer(b);
			PipedInputStream pi = new PipedInputStream(102400);
			channel.setPipedInputStream(pi);
			info.forwarder.messageReceived(info, channel, buffer);

			byte[] buf = new byte[16384];
			int avail;
			avail = pi.read(buf);
			ByteArrayBuffer bb = new ByteArrayBuffer(buf);

			String ln = getLine(bb);
			if (! ln.startsWith("HTTP/")) {
				status = "bad response";
				throw new IOException("Response does not start with HTTP/xx, but " + ln);
			}
			int i = ln.indexOf(' ');
			if (i < 0) {
				status = "bad response";
				throw new IOException("Invalid HTTP status line");
			}
			result.put("http-status", ln.substring(i+1, i+4));

			do {
				ln = getLine(bb);
				if (ln.length()==0) break;
			} while (true);

			ByteArrayOutputStream baos = new ByteArrayOutputStream(avail==16384 ? 65536 : avail);
			baos.write(buf, bb.rpos(), avail-bb.rpos());
			while ((avail = pi.read(buf)) > 0) {
				baos.write(buf, 0, avail);
			}
			pi.close();

			result.put ("jsonBody", mapper.readTree(baos.toByteArray()));

		} catch (Exception e) {
			status = "exception";
			result.put("exception", e.toString());
		}
		result.put("status", status);
		return result;
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
}
