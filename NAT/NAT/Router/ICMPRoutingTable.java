package Router;

public class ICMPRoutingTable {
	private final static int ICMP_INSIDE_SIZE = 4;
	private final static int ICMP_OUTSIDE_SIZE = 4;

	private byte[] ICMP_inside_IP;
	private int ICMP_identifier;
	private byte[] ICMP_outside_IP;
	private int ICMP_transition_identifier;

	public ICMPRoutingTable() {
		ICMP_inside_IP = new byte[ICMP_INSIDE_SIZE];
		ICMP_identifier = 0;
		ICMP_outside_IP = new byte[ICMP_OUTSIDE_SIZE];
		ICMP_transition_identifier = 0;
	}

	public void setICMPRoutingTable(byte[] inIP, byte[] outIP, int identifier, int transitionIdentifier) {
		System.arraycopy(inIP, 0, ICMP_inside_IP, 0, 4);
		System.arraycopy(outIP, 0, ICMP_outside_IP, 0, 4);
		ICMP_identifier = identifier;
		ICMP_transition_identifier = transitionIdentifier;
	}

	public byte[] getInside() {
		return this.ICMP_inside_IP;
	}

	public byte[] getOutside() {
		return this.ICMP_outside_IP;
	}

	public int getIndentifier() {
		return this.ICMP_identifier;
	}

	public int getTransitionIdentifier() {
		return this.ICMP_transition_identifier;
	}
}