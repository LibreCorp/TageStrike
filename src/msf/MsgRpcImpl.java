package msf;
import java.io.*;
import java.net.*;
import java.util.*;
import javax.net.ssl.*;
import org.msgpack.*;
import org.msgpack.type.*;
import org.msgpack.packer.*;
public class MsgRpcImpl extends RpcConnectionImpl {
	private URL apiUrl;
	private static final MessagePack messagePack = new MessagePack();
	private int connectTimeout = 15000; 
	private int readTimeout = 90000;    
	public static class MsfRpcException extends RuntimeException {
		public final Map<Value, Value> errorData;
		public MsfRpcException(String message, Map<Value, Value> errorData) {
			super(message);
			this.errorData = errorData;
		}
		public String getErrorClass() {
			return errorData.get(new RawValue("error_class")).toString();
		}
		public String getErrorBacktrace() {
			return errorData.get(new RawValue("error_backtrace")).toString();
		}
	}
	public MsgRpcImpl(String username, String password, String host, int port, boolean ssl, boolean debugf) throws Exception {
		if (ssl) {
			try {
				SSLContext sc = SSLContext.getInstance("TLS"); 
				sc.init(null, new TrustManager[] {
					new X509TrustManager() {
						public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
						public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
						public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
					}
				}, new java.security.SecureRandom());
				HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
				HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true); 
			} catch (Exception e) {
				throw new RuntimeException("Could not install the all-trusting SSL manager.", e);
			}
			apiUrl = new URL("https", host, port, "/api/1.0/");
		} else {
			apiUrl = new URL("http", host, port, "/api/1.0/");
		}
		Map results = exec("auth.login", new Object[]{username, password});
		if (results == null || !results.containsKey("token")) {
			throw new SecurityException("Authentication failed. Check your credentials.");
		}
		String tempToken = results.get("token").toString();
		results = exec("auth.token_generate", new Object[]{tempToken});
		if (results == null || !results.containsKey("token")) {
			throw new SecurityException("Failed to generate a permanent token. The server is probably having a bad day.");
		}
		this.rpcToken = results.get("token").toString();
	}
	private static Object unMsg(Value src) {
		if (src.isArrayValue()) {
			List<Value> l = src.asArrayValue().getElementList();
			List<Object> outList = new ArrayList<>(l.size());
			for(Value o : l)
				outList.add(unMsg(o));
			return outList;
		}
		if (src.isBooleanValue()) {
			return src.asBooleanValue().getBoolean();
		}
		if (src.isFloatValue()) {
			return src.asFloatValue().getDouble(); 
		}
		if (src.isIntegerValue()) {
			return src.asIntegerValue().getBigInteger();
		}
		if (src.isMapValue()) {
			Map<Value, Value> srcMap = src.asMapValue().map();
			Value errorClass = new RawValue("error_class");
			if (srcMap.containsKey(errorClass)) {
				String errorMessage = srcMap.get(new RawValue("error_message")).toString();
				throw new MsfRpcException(errorMessage, srcMap);
			}
			Map<String, Object> out = new HashMap<>();
			for (Map.Entry<Value, Value> entry : srcMap.entrySet()) {
				String key = unMsg(entry.getKey()).toString(); 
				Value val = entry.getValue();
				if(srcMap.size() == 1 && val.isRawValue() && (key.equals("payload") || key.equals("encoded"))) {
					out.put(key, val.asRawValue().getByteArray());
				} else {
					out.put(key, unMsg(val));
				}
			}
			return out;
		}
		if (src.isNilValue()) {
			return null;
		}
		if (src.isRawValue()) {
			try {
				return src.asRawValue().getString();
			} catch (UnsupportedEncodingException e) {
				return src.asRawValue().getByteArray();
			}
		}
		return src; 
	}
	protected void writeCall(String methodName, Object[] args) throws Exception {
		HttpURLConnection huc = (HttpURLConnection) apiUrl.openConnection();
		huc.setDoOutput(true);
		huc.setDoInput(true);
		huc.setUseCaches(false);
		huc.setRequestMethod("POST");
		huc.setRequestProperty("Content-Type", "binary/message-pack");
		huc.setConnectTimeout(this.connectTimeout);
		huc.setReadTimeout(this.readTimeout);
		List<Object> call = new LinkedList<>();
		call.add(methodName);
		Collections.addAll(call, args);
		try (OutputStream os = huc.getOutputStream()) {
			messagePack.write(os, call);
		}
		this.huc = huc; 
	}
	protected Object readResp() throws Exception {
		if (this.huc == null) {
			throw new IOException("readResp called before writeCall.");
		}
		try (InputStream is = this.huc.getInputStream()) {
			Value mpo = messagePack.read(is);
			return unMsg(mpo);
		} catch (IOException e) {
			try (InputStream es = ((HttpURLConnection) this.huc).getErrorStream()) {
				if (es != null) {
					Value mpo = messagePack.read(es);
					return unMsg(mpo); 
				}
			}
			throw e; 
		} finally {
			this.huc = null; 
		}
	}
}
