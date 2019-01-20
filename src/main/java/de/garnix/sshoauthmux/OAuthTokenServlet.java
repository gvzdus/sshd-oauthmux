package de.garnix.sshoauthmux;

import org.aeonbits.owner.ConfigFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class OAuthTokenServlet extends HttpServlet {

	private static final Logger logger = LoggerFactory.getLogger(OAuthTokenServlet.class);
	private static final HashMap<String,TokenEntry> tokenEntryMap = new HashMap<>(5);
	private static final MyConfig config = ConfigFactory.create(MyConfig.class);

	@Override
	public void service (HttpServletRequest request, HttpServletResponse response) throws IOException {
		if (logger.isDebugEnabled()) {
			Enumeration<String> e = request.getHeaderNames();
			while (e.hasMoreElements()) {
				String hn = e.nextElement();
				logger.debug ("Header " + hn + ": " + request.getHeader(hn));
			}
			Map<String,String[]> map = request.getParameterMap();
			for (Map.Entry<String,String[]> me : map.entrySet()) {
				for (String s : me.getValue())
					logger.debug ("Parameter " + me.getKey() + "=" + s);
			}
		}

		String grantType = request.getParameter("grant_type");
		String clientId = request.getParameter("client_id");
		String clientCred = request.getParameter("client_secret");
		String scope = request.getParameter("scope");
		String refresh_token = request.getParameter("refresh_token");
		String code = request.getParameter("code");

		if (!(config.oauthInClientID().equals(clientId)) ||
				!(config.oauthInClientAuthorization().equalsIgnoreCase(request.getHeader("Authorization")))) {
			logger.warn("OAuth call with missing or wrong client_credentials + client_id");
			for (Map.Entry<String,String[]> me : request.getParameterMap().entrySet()) {
				logger.info ("Parameter " + me.getKey() + " is " + me.getValue()[0]);
			}
			logger.info ("Authorization: " + request.getHeader("Authorization"));
			response.setStatus(404);
			return;
		}
		if (refresh_token==null && code!=null)
			refresh_token = code;
		response.setContentType("application/json");
		response.setHeader("Cache-Control", "no-store");
		PrintWriter wr = response.getWriter();
		if (refresh_token!=null) {
			TokenEntry te = null;
			synchronized (tokenEntryMap) {
				te = tokenEntryMap.get(refresh_token);
			}
			/*
			long token = Long.parseUnsignedLong(refresh_token, 16);
			int keyHC = Database.validateAccessToken(token);
			if (keyHC!=0) {
				String bearerToken = Integer.toHexString(keyHC) + '-' +
						Long.toHexString(Database.getBearerTokenForHc(keyHC));
				wr.print("{ \"access_token\":\"" + bearerToken + "\"," +
						" \"token_type\":\"bearer\"," +
						" \"expires_in\":3600," +
						" \"refresh_token\":\"" + refresh_token + "\"," +
						" \"scope\":\"create\" }");
				return;
			}
			*/
			boolean longTermBearerToken = false;
			Integer keyHC = null;
			Long token;
			if (te==null) {
				token = Long.parseUnsignedLong(refresh_token, 16);
				keyHC = Database.validateAccessToken(token);
			} else {
				keyHC = te.keyHC;
			}
			logger.info ("OAuth servlet received request for " + Integer.toHexString(keyHC).toUpperCase() + ", te=" + te);
			if (te!=null) {
				String bearerToken = null;
				if (te==null || te.bearerToken==null) {
					bearerToken = Integer.toHexString(te.keyHC) + '-' +
							Long.toHexString(Database.getBearerTokenForHc(keyHC));
					bearerToken = bearerToken.trim().toUpperCase();
				} else {
					bearerToken = te.bearerToken;
					longTermBearerToken = true;
				}
				wr.print("{ \"access_token\":\"" + bearerToken + "\"," +
						" \"token_type\":\"bearer\"," +
						(longTermBearerToken ? "" : " \"expires_in\": 3600," ) +
						(longTermBearerToken ? "" : " \"refresh_token\":\"" + refresh_token + "\"," ) +
						" \"scope\":\"fhem\" }");
				return;
			}
		}
		response.setStatus(401);
		wr.print("{ \"error\":\"invalid_grant\" }");
	}

	public static void setCode (String code, int keyHC, String bearerToken) {
		synchronized (tokenEntryMap) {
			Iterator<Map.Entry<String, TokenEntry>> it = tokenEntryMap.entrySet().iterator();
			long now = System.currentTimeMillis();
			while (it.hasNext()) {
				Map.Entry<String, TokenEntry> me = it.next();
				if (me.getValue().isExpired(now))
					it.remove();
			}
			tokenEntryMap.put(code, new TokenEntry(keyHC, bearerToken));
		}
	}

	static class TokenEntry {
		final long timestamp;
		final int keyHC;
		final String bearerToken;

		TokenEntry(int keyHC, String bearerToken) {
			this.timestamp = System.currentTimeMillis();
			this.keyHC = keyHC;
			this.bearerToken = bearerToken;
		}

		boolean isExpired(long now) {
			return timestamp + 300000 < now;
		}

		public int getKeyHC() {
			return keyHC;
		}

		public String getBearerToken() {
			return bearerToken;
		}
	}
}