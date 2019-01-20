package de.garnix.sshoauthmux;

import org.aeonbits.owner.ConfigFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.fluent.Form;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.fluent.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Map;

public class OAuthProxyServlet extends HttpServlet {

	private static final Logger logger = LoggerFactory.getLogger(OAuthProxyServlet.class);
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

		Form f = Form.form().
				add("client_id", config.oauthOutClientID()).
				add("client_secret", config.oauthOutClientSecret()).
				add("grant_type", request.getParameter("grant_type"));
		String v;
		v = request.getParameter("code");
		if (v!=null) f.add("code", v);
		v = request.getParameter("refresh_token");
		if (v!=null) f.add("refresh_token", v);
		v = request.getParameter("scope");
		if (v!=null) f.add("scope", v);

		// TODO: Implement error handling
		try {
			Request.Post(config.oauthOutURL())
					.bodyForm(f.build()).execute().handleResponse(new ResponseHandler<Response>() {
				@Override
				public Response handleResponse(HttpResponse remRsp) throws IOException {
					StatusLine statusLine = remRsp.getStatusLine();
					HttpEntity entity = remRsp.getEntity();
					response.setStatus(statusLine.getStatusCode());
					if (statusLine.getStatusCode()>=400)
						logger.warn("Bad HTTP response from OAuthRemote: " + statusLine.toString());
					if (entity != null) {
						response.setContentType(entity.getContentType().getValue());
						entity.writeTo(response.getOutputStream());
					}
					return null;
				}
			});
		} catch (HttpResponseException hre) {
			try {
				logger.warn("HttpResponseError " + hre);
			} catch (Exception e) {
				logger.error("Exception on HRE-Processing: " + e, e);
			}
		}

	}
}