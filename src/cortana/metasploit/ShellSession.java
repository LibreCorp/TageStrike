package cortana.metasploit;
import java.util.*;
import java.awt.*;
import java.awt.event.*;
import msf.*;
import java.math.BigInteger;
import java.security.SecureRandom;
public class ShellSession implements Runnable {
	protected RpcConnection connection;
	protected RpcConnection dserver;
	protected LinkedList<ShellCallback> listeners = new LinkedList<>();
	protected LinkedList<Command> commands  = new LinkedList<>();
	protected String        session;
	protected long          commandTimeout; 
	private static class Command {
		public Object   token;
		public String   text;
		public long	    start = System.currentTimeMillis();
	}
	public static interface ShellCallback {
		public void commandComplete(String session, Object token, String response);
		public void commandUpdate(String session, Object token, String response);
		public void commandFailed(String session, Object token, Exception reason);
	}
	public void addListener(ShellCallback l) {
		synchronized (listeners) {
			listeners.add(l);
		}
	}
	protected void fireEvent(Command command, String output, boolean done) {
		synchronized (listeners) {
			for (ShellCallback l : listeners) {
				if (done)
					l.commandComplete(session, command != null ? command.token : null, output);
				else
					l.commandUpdate(session, command != null ? command.token : null, output);
			}
		}
	}
	protected void fireFailure(Command command, Exception reason) {
		synchronized (listeners) {
			for (ShellCallback l : listeners) {
				l.commandFailed(session, command != null ? command.token : null, reason);
			}
		}
	}
	public ShellSession(RpcConnection connection, RpcConnection dserver, String session) {
		this(connection, dserver, session, 90000); 
	}
	public ShellSession(RpcConnection connection, RpcConnection dserver, String session, long commandTimeout) {
		this.connection = connection;
		this.dserver    = dserver;
		this.session    = session;
		this.commandTimeout = commandTimeout; 
		new Thread(this).start();
	}
	private final SecureRandom random = new SecureRandom();
	protected void processCommand(Command c) {
		try {
			String marker = new BigInteger(130, random).toString(32);
			String endMarker = "\n" + marker + "\n"; 
			String commandWithMarker = c.text + "\necho " + marker + "\n";
			connection.execute("session.shell_write", new Object[] { session, commandWithMarker });
			StringBuilder output = new StringBuilder();
			long start = System.currentTimeMillis();
			while ((System.currentTimeMillis() - start) < this.commandTimeout) {
				Map response = readResponse();
				String data = response.get("data") != null ? response.get("data").toString() : "";
				if (data.length() > 0) {
					output.append(data);
					fireEvent(c, data, false); 
					if (output.toString().endsWith(endMarker)) {
						String finalOutput = output.substring(0, output.length() - endMarker.length());
						fireEvent(c, finalOutput, true);
						return; 
					}
				}
				Thread.sleep(150); 
			}
			throw new Exception("Command timed out after " + (this.commandTimeout / 1000) + " seconds.");
		}
		catch (Exception ex) {
			System.err.println(session + " -> command '" + c.text + "' failed: " + ex.getMessage());
			fireFailure(c, ex); 
		}
	}
	public void addCommand(Object token, String text) {
		if (text == null || text.trim().isEmpty()) {
			return; 
		}
		synchronized (commands) {
			Command temp = new Command();
			temp.token = token;
			temp.text  = text;
			commands.add(temp);
		}
	}
	protected Command grabCommand() {
		synchronized (commands) {
			return commands.pollFirst();
		}
	}
	public void acquireLock() {
		while (true) {
			try {
				Map temp = (Map)dserver.execute("armitage.lock", new Object[] { session, "Cortana" });
				if (temp != null && !temp.containsKey("error")) {
					return; 
				}
				Thread.sleep(500);
			}
			catch (Exception ex) {
				System.err.println("Failed trying to acquire lock for " + session + ": " + ex.getMessage());
				try { Thread.sleep(1000); } catch (InterruptedException ie) {}
			}
		}
	}
	public void run() {
		boolean needLock = true;
		while (true) {
			try {
				Command next = grabCommand();
				if (next != null) {
					if (needLock) {
						acquireLock();
						needLock = false;
					}
					processCommand(next);
					Thread.sleep(50); 
				}
				else {
					if (!needLock) {
						dserver.execute("armitage.unlock", new Object[] { session });
						needLock = true;
					}
					Thread.sleep(500); 
				}
			}
			catch (Exception ex) {
				System.err.println("Main loop for session " + session + " had a failure: " + ex.getMessage());
				try {
					if (!needLock) {
						dserver.execute("armitage.unlock", new Object[] { session });
						needLock = true;
					}
					Thread.sleep(5000); 
				} catch (Exception innerEx) {
				}
			}
		}
	}
	private Map readResponse() throws Exception {
		return (Map)(connection.execute("session.shell_read", new Object[] { session }));
	}
}
