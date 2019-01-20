package de.garnix.sshoauthmux;

import org.aeonbits.owner.ConfigFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ParameterServletFilter implements Filter {

	private static final MyConfig config = ConfigFactory.create(MyConfig.class);

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {

	}

	private static final Pattern headerParser = Pattern.compile("^([^ :]+):\\s*(.*)$");
	private static final Logger logger = LoggerFactory.getLogger(AlexaCommandServlet.class);

	@Override
	@SuppressWarnings("unchecked")
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest req = (HttpServletRequest) request;
		HttpSession session = req.getSession();
		Map<String,String> pmap = (Map<String, String>) session.getAttribute("pmap");
		if (pmap==null)
			pmap = new HashMap<>();
		Enumeration<String> params = req.getParameterNames();
		while(params.hasMoreElements()){
			String name = params.nextElement();
			String value = request.getParameter(name);
			pmap.put(name, value.trim());
			if ("authkey".equals(name)) {
				value = value.trim().toUpperCase();
				value = value.replaceAll("[^A-Z0-9-]", "");
				String[] arr = value.split("-");
				if (arr.length==3)
					pmap.put ("bearerToken", (arr[0] + "-" + arr[2]).trim());
				session.setAttribute("userid", arr[0]);
			}
		}
		for (String hd : config.responseHeaders()) {
			Matcher m = headerParser.matcher(hd);
			if (m.matches())
				((HttpServletResponse)response).setHeader(m.group(1), m.group(2));
			else
				logger.warn ("Cannot apply pattern to responseHeaders value " + hd);
		}
		session.setAttribute("pmap", pmap);
		chain.doFilter(request, response);
	}

	@Override
	public void destroy() {

	}
}
