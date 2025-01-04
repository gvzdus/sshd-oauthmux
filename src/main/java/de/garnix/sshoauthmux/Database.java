package de.garnix.sshoauthmux;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.digest.Digest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.BinaryJedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

import java.io.IOException;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class Database {

	private static final Logger log = LoggerFactory.getLogger(Database.class);
	private static final ObjectMapper mapper = new ObjectMapper();

	//	private static BinaryJedis jedis = new BinaryJedis("localhost");
	private static final byte[] KEY_KEY = { 'K', 'E', 'Y' };
	private static final byte[] KEY_LAST_USAGE = { 'L', 'a', 's', 't', 'U', 's', 'a', 'g', 'e' };
	private static final byte[] KEY_PASSWORD = { 'P', 'W', 'H', 'a', 's', 'h' };
	private static final byte[] KEY_EMAIL = { 'E', 'm', 'a', 'i', 'l' };
	private static final byte[] KEY_PATH = { 'P', 'a', 't', 'h' };
	private static final byte[] KEY_CREATED = { 'C', 'r', 'e', 'a', 't', 'e', 'd' };
//	private static final byte[] KEY_ID = { 'I', 'd' };

	private static final SecureRandom secrand = new SecureRandom();

	static int badHashCode(PublicKey k) {
		return k.hashCode();
	}

	static int goodHashCode(PublicKey k) {
		return Arrays.hashCode(k.getEncoded());
	}

	private static JedisPool jedisPool;
	static {
		JedisPoolConfig config = new JedisPoolConfig();
		config.setMaxIdle(8);
		config.setMinIdle(1);
		config.setMaxTotal(180);
		config.setTestOnBorrow(true);
		jedisPool = new JedisPool(config, "localhost");
	}


	/**
	 * returns the UID for a public Cert, used by PseudoShellCommand.start
	 * @param key SSH certificate
	 * @return hc, otherwise 0
	 */
	static int searchClientCert (PublicKey key) {

		try (BinaryJedis jedis = jedisPool.getResource()) {
			return searchClientCert(jedis, key);
		}
	}

	static int searchClientCert (BinaryJedis jedis, PublicKey key) {
		int uid;
		for (uid = goodHashCode(key); uid != 0 && uid != -1; uid++) {
			final byte[] hkey = getPublicKeyHCKey(uid); // 1234-prefix
			byte[] dbKey = jedis.hget(hkey, KEY_KEY);
			if (dbKey != null) {
				if (Arrays.equals(dbKey, key.getEncoded())) {
					if (log.isDebugEnabled())
						log.debug("Found uid " + Integer.toHexString(uid) + " by goodhash for key");
					return uid;
				} else
					log.warn("GoodHC " + Integer.toHexString(uid) + " used by multiple keys");
			} else
				break;
		}
		for (uid = badHashCode(key); uid != 0 && uid != -1; uid++) {
			final byte[] hkey = getPublicKeyHCKey(uid); // 1234-prefix
			byte[] dbKey = jedis.hget(hkey, KEY_KEY);
			if (dbKey != null) {
				if (Arrays.equals(dbKey, key.getEncoded())) {
					if (log.isDebugEnabled())
						log.debug("Found uid " + Integer.toHexString(uid) + " by badhash for key");
					return uid;
				} else
					log.warn("OBadHC " + Integer.toHexString(uid) + " used by multiple keys");
			} else
				break;
		}
		log.debug ("Not found in DB");
		return 0;
	}

	public static String getUserInfoJson (String password) throws IOException {
		UserInfo u = getUserInfo(password);
		if (u==null) return "{}";
		return mapper.writeValueAsString(u);
	}

	/** Returns for a full registration key the Userinfo
	 * Verifies the password, used in web
	 * @param password registrationkey
	 * @return userinfo found, null otherwise
	 */
	public static UserInfo getUserInfo(String password) {
		if (password==null)
			return null;
		boolean isDebug = log.isDebugEnabled();
		if (isDebug) log.debug("Checking IDENT " + password);
		String[] args = password.split("-");
		Integer uid;
		Long passwordLong;
		try {
			uid = Integer.parseUnsignedInt(args[0], 16);
			passwordLong = Long.parseUnsignedLong(args[1], 16);
		} catch (Exception e) {
			if (isDebug) log.debug("Password was not parseable: ", e);
			return null;
		}
		UserInfo u = getUserInfo(uid);
		if (u==null) {
			if (isDebug) log.debug("UID " + Integer.toHexString(uid) + " not found in DB");
			return null;
		}
		if (Arrays.equals(getDigest(passwordLong), u.pwhash)) {
			if (isDebug) log.debug("Found user with matching password");
			return u;
		} else {
			if (isDebug) log.debug("The password does not match");
			return null;
		}
	}

	/**
	 * Returns the userinfo for a keyHc, and a public key
	 *  used in ControlCommand.start and getUserInfo
	 * @param uid userid
	 * @return userinfo structure
	 */
	public static UserInfo getUserInfo (int uid) {
		final byte[] hkey = getPublicKeyHCKey(uid);
		try (BinaryJedis jedis = jedisPool.getResource()) {

			Map<byte[], byte[]> result = jedis.hgetAll(hkey);
			if (result == null || result.size() == 0)
				return null;

			UserInfo u = new UserInfo();
			byte[] t = result.get(KEY_KEY);
			u.publicKey = t;

			t = result.get(KEY_CREATED);
			if (t != null)
				u.created = ByteBuffer.wrap(t).getLong();
			t = result.get(KEY_LAST_USAGE);
			if (t != null)
				u.lastActive = ByteBuffer.wrap(t).getLong();

			t = result.get(KEY_EMAIL);
			if (t != null)
				u.email = new String(t);

			t = result.get(KEY_PATH);
			u.path = t != null ? new String(t) : "/";

			u.pwhash = result.get(KEY_PASSWORD);
			u.keyId = uid;

			return u;
		}

	}


	/**
	 * Returns the userinfo for a keyHc, and a public key
	 *  used in ControlCommand.start and getUserInfo
	 * @param key public key
	 * @return
	 */
	static UserInfo getUserInfo (PublicKey key) {

		try (BinaryJedis jedis = jedisPool.getResource()) {
			int uid = searchClientCert(jedis, key);
			final byte[] hkey = getPublicKeyHCKey(uid); // 1234-prefix

			Map<byte[], byte[]> result = jedis.hgetAll(hkey);
			if (result == null || result.size() == 0)
				return null;

			UserInfo u = new UserInfo();
			byte[] t = result.get(KEY_KEY);
			if (t == null || (key != null && !Arrays.equals(t, key.getEncoded())))
				return null;
			u.publicKey = t;

			t = result.get(KEY_CREATED);
			if (t != null)
				u.created = ByteBuffer.wrap(t).getLong();
			t = result.get(KEY_LAST_USAGE);
			if (t != null)
				u.lastActive = ByteBuffer.wrap(t).getLong();

			t = result.get(KEY_EMAIL);
			if (t != null)
				u.email = new String(t);

			t = result.get(KEY_PATH);
			u.path = t != null ? new String(t) : "/";

			u.pwhash = result.get(KEY_PASSWORD);

			u.keyId = uid;

			return u;
		}
	}

	/**
	 * Stores a certificate in the database including additional information
	 * Called by ControlCommand.register
	 * @param key clients public key
	 * @param email clients email address (obsolete)
	 * @param path clients server path (not used)
	 * @param keyhash SHA256-hash of password for web authenitication
	 * @return generated user-id as string
	 */
	static String insertClientCert (PublicKey key, String email, String path, String keyhash) {
		try (BinaryJedis jedis = jedisPool.getResource()) {
			int uid;
			for (uid = goodHashCode(key); uid != 0 && uid != -1; uid++) {
				final byte[] hkey = getPublicKeyHCKey(uid); // 1234-prefix
				byte[] dbKey = jedis.hget(hkey, KEY_KEY);
				if (dbKey != null) {
					if (Arrays.equals(dbKey, key.getEncoded()))
						break; // already stored
					else
						log.warn("On Insert: GoodHC " + uid + " used by multiple keys");
				} else
					break;
			}
			if (uid == 0 || uid == -1) return "";

			final byte[] hkey = getPublicKeyHCKey(uid);
			long r = jedis.hset(hkey, KEY_KEY, key.getEncoded());
			if (log.isDebugEnabled())
				log.debug("Storing Key for " + Integer.toHexString(uid) + " resulted in " + r);
			ByteBuffer bb2;

			bb2 = ByteBuffer.allocate(8).putLong(System.currentTimeMillis());
			((Buffer) bb2).flip();
			r = jedis.hset(hkey, KEY_LAST_USAGE, bb2.array());
			r = jedis.hset(hkey, KEY_CREATED, bb2.array());
			if (log.isDebugEnabled())
				log.debug("Storing lastUpdate for " + Integer.toHexString(uid) + " resulted in " + r);
			if (email != null) {
				r = jedis.hset(hkey, KEY_EMAIL, email.getBytes());
				if (log.isDebugEnabled())
					log.debug("Storing email for " + Integer.toHexString(uid) + " resulted in " + r);
			}
			if (!"/".equals(path)) {
				r = jedis.hset(hkey, KEY_PATH, path.getBytes());
				if (log.isDebugEnabled())
					log.debug("Storing path for " + Integer.toHexString(uid) + " resulted in " + r);
			}

			// Creating user info
			if (keyhash == null) {
				long secret = secrand.nextLong();
				byte hash[] = getDigest(secret);
				r = jedis.hset(hkey, KEY_PASSWORD, hash);
				if (log.isDebugEnabled())
					log.debug("Storing PWHash for " + Integer.toHexString(uid) + " resulted in " + r);

				// Reverse lookup for PW Hash:
				String s = jedis.set(getPwHashKey(hash), hkey);
				if (log.isDebugEnabled())
					log.debug("Storing PWHash by HashKey for " + Integer.toHexString(uid) + " resulted in " + s);

				return (Integer.toHexString(uid) + "-" + Long.toHexString(secret)).toUpperCase();
			} else {
				byte hash[] = unhexlify(keyhash);
				r = jedis.hset(hkey, KEY_PASSWORD, hash);
				if (log.isDebugEnabled())
					log.debug("Storing PWHash for " + Integer.toHexString(uid) + " resulted in " + r);
				return (Integer.toHexString(uid) + "-...").toUpperCase();
			}
		}
	}

	/**
	 * Removes a certificate from the database
	 * @param key full public key
	 * @return number of entries deleted
	 */

	static long removeClientCert (PublicKey key) {

		try (BinaryJedis jedis = jedisPool.getResource()) {
			int uid = searchClientCert(jedis, key);
			final byte[] hkey = getPublicKeyHCKey(uid);
			byte[] pwash = jedis.hget(hkey, KEY_PASSWORD);
			if (pwash != null && pwash.length > 0)
				jedis.del(pwash);

			long r = jedis.hdel(hkey, KEY_CREATED, KEY_KEY, KEY_LAST_USAGE, KEY_PASSWORD, KEY_PATH, KEY_EMAIL);
			if (log.isDebugEnabled())
				log.debug("Deleting for " + Integer.toHexString(uid) + " resulted in " + r);
			return r;
		}
	}

	/**
	 * Removes a certificate from the database
	 * @param uid full public key
	 * @return number of entries deleted
	 */

	public static long deleteUid (int uid) {
		try (BinaryJedis jedis = jedisPool.getResource()) {
			final byte[] hkey = getPublicKeyHCKey(uid);
			byte[] pwash = jedis.hget(hkey, KEY_PASSWORD);
			if (pwash != null && pwash.length > 0)
				jedis.del(pwash);

			long r = jedis.hdel(hkey, KEY_CREATED, KEY_KEY, KEY_LAST_USAGE, KEY_PASSWORD, KEY_PATH, KEY_EMAIL);
			if (log.isDebugEnabled())
				log.debug("Deleting for " + Integer.toHexString(uid) + " resulted in " + r);
			return r;
		}
	}

	private static byte[] getDigest(long secret) {
		ByteBuffer bb = ByteBuffer.allocate(8).putLong(secret);
		((Buffer)bb).flip();
		Digest digest = BuiltinDigests.sha256.create();
		try {
			digest.init();
			digest.update(bb.array());
			return digest.digest();
		} catch (Exception e) {
			log.warn ("Creating SHA256 digest raised " + e, e);
			return null;
		}
	}

	private static byte[] getPublicKeyKey(PublicKey key) {
		return getPublicKeyHCKey(key.hashCode());
	}

	private static byte[] getPublicKeyHCKey(int hashcode) {
		ByteBuffer bb = ByteBuffer.allocate(6).putShort((short) 0x1234).putInt(hashcode);
		((Buffer)bb).flip();
		return bb.array();
	}

	private static byte[] getPublicKeyHCCountKey(int hashcode) {
		ByteBuffer bb = ByteBuffer.allocate(6).putShort((short) 0x4731).putInt(hashcode);
		((Buffer)bb).flip();
		return bb.array();
	}

	private static byte[] getPwHashKey(byte[] hash) {
		ByteBuffer bb = ByteBuffer.allocate(36).putShort((short) 0x1210).put(hash);
		((Buffer)bb).flip();
		return bb.array();
	}

	private static byte[] getTokenKey(long atoken) {
		ByteBuffer bb = ByteBuffer.allocate(10).putShort((short) 0x623A).putLong(atoken);
		((Buffer)bb).flip();
		return bb.array();
	}

	public static int validateAccessToken(long token) {
		try (BinaryJedis jedis = jedisPool.getResource()) {

			byte[] r1 = jedis.get(getTokenKey(token));
			if (r1 == null) {
				log.info("Validation of access-token " + Long.toHexString(token) + " failed - no such token found");
				return 0;
			}
			byte[] r2 = jedis.hget(r1, KEY_LAST_USAGE);
			if (r2 != null) {
				log.debug("Validation of access-token " + Long.toHexString(token) + " succeeded");
				return ByteBuffer.wrap(r1, 2, 4).getInt();
			} else {
				log.info("Validation of access-token " + Long.toHexString(token) + " failed - no key found");
				return 0;
			}
		}
	}

	static final HashMap<Long,Integer> bearerTokens = new HashMap<>();

	static long getBearerTokenForHc(int hc) {
		while (true) {
			long bearerToken = secrand.nextLong();
			synchronized (bearerTokens) {
				Integer oldValue = bearerTokens.put (bearerToken, hc);
				if (oldValue!=null) {
					bearerTokens.put (bearerToken, oldValue);
					continue;
				}
			}
			return bearerToken;
		}
	}

	public static Integer validateBearerToken(long bearerToken) {
		synchronized (bearerTokens) {
			return bearerTokens.get(bearerToken);
		}
	}

	// Thanks to stackoverflow again...:

	/**
	 *
	 * @param hexInput string with hex characters
	 * @return buffer corresponding to hex input
	 */
	public static byte[] unhexlify(String hexInput) {
		int strlen = hexInput.length();
		if (strlen>0 && strlen%2!=0) {
			throw new RuntimeException("odd-length string");
		}
		byte[] ret = new byte[strlen/2];
		for (int i=0; i<strlen; i+=2) {
			int a = Character.digit(hexInput.charAt(i),0x10);
			int b = Character.digit(hexInput.charAt(i+1),0x10);
			if (a==-1 || b==-1) {
				throw new RuntimeException("non-hex digit");
			}
			ret[i/2] = (byte) ((a<<4)+b);
		}
		return ret;
	}

	static class UserInfo {
		byte[] publicKey;
		String email;
		String path;
		byte[] pwhash;
		long lastActive;
		long created;
		int keyId;

		public String getEmail() {
			return email;
		}

		public String getPath() {
			return path;
		}

		public long getLastActive() {
			return lastActive;
		}

		public long getCreated() {
			return created;
		}

		public String getKeyId() {
			return keyId!=0 ? Integer.toHexString(keyId) : "";
		}

		public String getRemoteAddress() {
			if (keyId!=0) {
				SshClientConnectInfo info = SshClientConnectInfo.getBySession(keyId);
				if (info != null && info.session != null)
					return info.session.getClientAddress().toString();
			}
			return null;
		}

		public boolean isOnline() {
			if (keyId!=0) {
				SshClientConnectInfo info = SshClientConnectInfo.getBySession(keyId);
				if (info != null && info.session != null)
					return !info.session.isClosing();
			}
			return false;
		}

		public boolean isWithForwarder() {
			if (keyId!=0) {
				SshClientConnectInfo info = SshClientConnectInfo.getBySession(keyId);
				if (info != null && info.session != null)
					return info.forwarder()!=null;
			}
			return false;
		}

		public String generateAccessToken(boolean store) {
			long tokenLong = secrand.nextLong();
			String tokenStr = Long.toHexString(tokenLong);
			if (store)
				try (BinaryJedis jedis = jedisPool.getResource()) {
					jedis.set(getTokenKey(tokenLong), getPublicKeyHCKey(keyId));
				}
			return tokenStr;
		}

	}




}
