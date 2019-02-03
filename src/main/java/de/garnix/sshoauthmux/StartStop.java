package de.garnix.sshoauthmux;

import org.aeonbits.owner.ConfigFactory;
import org.aeonbits.owner.event.ReloadEvent;
import org.aeonbits.owner.event.RollbackBatchException;
import org.aeonbits.owner.event.TransactionalReloadListener;
import org.apache.log4j.Level;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.io.IOException;
import java.util.Properties;

public class StartStop implements ServletContextListener {

	private static Logger log = LoggerFactory.getLogger(StartStop.class);
	private static Thread sessionCleaner = null;
	private static MyConfig config = ConfigFactory.create(MyConfig.class);
	private static Properties lastProperties;

	@Override
	public void contextInitialized(ServletContextEvent sce) {


		config.addReloadListener(new TransactionalReloadListener() {

			@Override
			public void reloadPerformed(ReloadEvent event) {
				log.info ("reloadPerformed");
				Properties newProperties = event.getNewProperties();
				if (newProperties!=lastProperties) {
					if (newProperties.get("logLevel")!=null)
						setLogLevel ();
				}
			}

			public void beforeReload(ReloadEvent event)
		        throws RollbackBatchException {
				log.info ("beforeReload");
		    }
		});
		setLogLevel();

		try {
			// TODO: Make this configurable
			Server.start(config.sshPort());

			sessionCleaner = new Thread(new Runnable() {
				String lastLogLevel = "xxx";

				@Override
				public void run() {
					while (! Thread.interrupted()) {
						try {
							Thread.sleep(3000);
						} catch (InterruptedException ioe) {
							break;
						}
						SshClientConnectInfo.closeEofSessions();
						if (! lastLogLevel.equals(config.logLevel())) {
							setLogLevel();
							lastLogLevel = config.logLevel();
						}
					}
				}
			});
			sessionCleaner.start();

		} catch (IOException ioe) {
			log.error("Startup failed: " + ioe, ioe);
		}
	}

	@Override
	public void contextDestroyed(ServletContextEvent sce) {

		sessionCleaner.interrupt();
		Server.stop();

	}

	public static void setLogLevel() {
		String logLevel = config.logLevel();
		org.apache.log4j.Logger root = org.apache.log4j.Logger.getRootLogger()     ;
		boolean logLevelRecognized = true;
		if ("DEBUG".equalsIgnoreCase(logLevel)) {
			root.setLevel(Level.DEBUG);
		} else if ("INFO".equalsIgnoreCase(logLevel)) {
			root.setLevel(Level.INFO);
		} else if ("WARN".equalsIgnoreCase(logLevel)) {
			root.setLevel(Level.WARN);
		} else if ("ERROR".equalsIgnoreCase(logLevel)) {
			root.setLevel(Level.ERROR);
		} else if ("FATAL".equalsIgnoreCase(logLevel)) {
			root.setLevel(Level.FATAL);
		} else {
			logLevelRecognized = false;
		}
		if (logLevelRecognized)
			log.info("LogLevel changed to " + logLevel);
		else
			log.warn("LogLevel '" + logLevel + "' is invalid");
	}
}
