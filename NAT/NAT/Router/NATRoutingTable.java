package Router;

public class NATRoutingTable {
	private final static int NAT_INSIDE_SIZE = 4;
	private final static int NAT_OUTSIDE_SIZE = 4;

	private byte[] NAT_inside_IP;
	private int NAT_inside_Port_Num;
	private byte[] NAT_outside_IP;
	private int NAT_transition_Port_Num;

	public NATRoutingTable() {
		NAT_inside_IP = new byte[NAT_INSIDE_SIZE];
		NAT_inside_Port_Num = 0;
		NAT_outside_IP = new byte[NAT_OUTSIDE_SIZE];
		NAT_transition_Port_Num = 0;
	}

	public void setNATRoutingTable(byte[] inIP, byte[] outIP, int inPortNum, int transitionPortNum) {
		System.arraycopy(inIP, 0, NAT_inside_IP, 0, 4);
		System.arraycopy(outIP, 0, NAT_outside_IP, 0, 4);
		NAT_inside_Port_Num = inPortNum;
		NAT_transition_Port_Num = transitionPortNum;
	}

	public byte[] getInside() {
		return this.NAT_inside_IP;
	}

	public byte[] getOutside() {
		return this.NAT_outside_IP;
	}

	public int getInsidePort() {
		return this.NAT_inside_Port_Num;
	}

	public int getTransitionPort() {
		return this.NAT_transition_Port_Num;
	}
}