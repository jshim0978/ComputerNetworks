package Router;

import java.util.Arrays;
import java.util.Timer;
import java.util.TimerTask;

import Router.TCPLayer.PeriodicHandler;

public class ICMPLayer extends BaseLayer {
	final static int ICMP_MAX_SIZE = 65507;
	final static int ICMP_HEAD_SIZE = 8;
	static int DEFAULT_IDEN = 5000;
	static int TRANSLATED_IDEN = 2323;

	byte[] ICMP_head;
	byte[] ICMP_type;
	byte[] ICMP_code;
	byte[] ICMP_checksum;
	byte[] ICMP_identifier;
	byte[] ICMP_sequence;

	byte[] icmp_data;

	static int NATTableCount = 0;

	public ICMPLayer(String layerName) {
		super(layerName);
		resetHeader();
	}

	void resetHeader() {
		ICMP_head = new byte[ICMP_HEAD_SIZE];
		ICMP_type = new byte[1];
		ICMP_code = new byte[1];
		ICMP_checksum = new byte[2];
		ICMP_identifier = new byte[2];
		ICMP_sequence = new byte[2];
	}

	public static int byte2Int(byte[] src) {

		int s1 = src[0] & 0xFF;
		int s2 = src[1] & 0xFF;

		return ((s1 << 8) + (s2 << 0));
	}

	void ICMP_received(byte[] data, byte[] dst_ip, byte[] src_ip, byte[] ip_header_data) {
		System.out.println(">>ICMP RECEIVED");
		byte type = data[0];

		if (type == 0x08) {
			this.ICMP_request_recieved(data, dst_ip, src_ip, ip_header_data);
		} else if (type == 0x00) {
			this.ICMP_response_received(data, dst_ip, src_ip, ip_header_data);
		}
	}

	void ICMP_response_received(byte[] data, byte[] dst_ip, byte[] src_ip, byte[] ip_header_dat) {
//		byte[] decapsulation = Arrays.copyOfRange(data, ICMP_HEAD_SIZE, data.length);
		System.out.println("ICMP_reponse received - src ip:" + ApplicationLayer.byte2IP(src_ip) + "dst_ip:"
				+ ApplicationLayer.byte2IP(dst_ip));
		synchronized (ApplicationLayer.ICMPRoutingTable) {
			ICMP_identifier[0] = data[4];
			ICMP_identifier[1] = data[5];

			int iden = byte2Int(ICMP_identifier);

			for (int i = 0; i < ApplicationLayer.ICMPRoutingIndex; i++) {
				if (iden == (ApplicationLayer.ICMPRoutingTable[i]).getTransitionIdentifier()) {

					byte[] dst_iden = ApplicationLayer
							.Int2byte((ApplicationLayer.ICMPRoutingTable[i]).getIndentifier());
					System.out.print("foward packet : OUT-IN");
					sendICMP(data, src_ip, dst_iden, (ApplicationLayer.ICMPRoutingTable[i]).getInside(), ip_header_dat);
					break;
				}
			}
		}
	}

	public static int ipByte2Int(byte[] src) {
		int s1 = src[0] & 0xFF;
		int s2 = src[1] & 0xFF;
		int s3 = src[2] & 0xFF;
		int s4 = src[3] & 0xFF;

		return ((s1 << 24) + (s2 << 16) + (s3 << 8) + (s4 << 0));
	}

	void ICMP_request_recieved(byte[] data, byte[] dst_ip, byte[] src_ip, byte[] ip_header_data) {
		System.out.println("ICMP_request received - src ip:" + ApplicationLayer.byte2IP(src_ip) + "dst_ip:"
				+ ApplicationLayer.byte2IP(dst_ip));
		synchronized (ApplicationLayer.ICMPRoutingTable) {
//			byte[] decapsulation = Arrays.copyOfRange(data, ICMP_HEAD_SIZE, data.length);

			ICMP_identifier[0] = data[4];
			ICMP_identifier[1] = data[5];
			byte[] outside_ip = ((IPLayer) this.getUnderLayer()).getPublicIP();

			int iden = byte2Int(ICMP_identifier);

			// ICMP 요청 확인 하고 연결 정보 존재하는지 확인 후 table 갱신
			if (ApplicationLayer.ICMPRoutingIndex == 0) {
				ApplicationLayer.ICMPRoutingTable[0] = new ICMPRoutingTable();
				ApplicationLayer.ICMPRoutingTable[0].setICMPRoutingTable(src_ip, outside_ip, iden, TRANSLATED_IDEN);
				setMapTable(ApplicationLayer.ICMPRoutingIndex);
				startPeriodicTimer(ApplicationLayer.ICMPRoutingIndex);
				// send 해야됨
				ApplicationLayer.ICMPRoutingIndex++;
				updateGUIICMPTable();
				byte[] src_iden = ApplicationLayer
						.Int2byte((ApplicationLayer.ICMPRoutingTable[0]).getTransitionIdentifier());
				System.out.print("foward packet : IN-OUT");
				sendICMP(data, outside_ip, src_iden, dst_ip, ip_header_data);
			} else {
				int hasBeen = 1;
				int pos = 0;

				for (int i = 0; i < ApplicationLayer.ICMPRoutingIndex; i++) {
					if (!Arrays.equals(src_ip, (ApplicationLayer.ICMPRoutingTable[i]).getInside())) {
						hasBeen = 0;
					} else if (Arrays.equals(src_ip, (ApplicationLayer.ICMPRoutingTable[i]).getInside())
							&& iden != ApplicationLayer.ICMPRoutingTable[i].getIndentifier()) {
						hasBeen = 0;
					} else if (Arrays.equals(src_ip, (ApplicationLayer.ICMPRoutingTable[i]).getInside())
							&& iden == ApplicationLayer.ICMPRoutingTable[i].getIndentifier()) {
						pos = i;
						hasBeen = 1;
						break;
					}
				}
				if (hasBeen == 0) {
					ApplicationLayer.ICMPRoutingTable[ApplicationLayer.ICMPRoutingIndex] = new ICMPRoutingTable();
					ApplicationLayer.ICMPRoutingTable[ApplicationLayer.ICMPRoutingIndex].setICMPRoutingTable(src_ip,
							outside_ip, iden, get_defaul_port());
					setMapTable(ApplicationLayer.ICMPRoutingIndex);
					startPeriodicTimer(ApplicationLayer.ICMPRoutingIndex);
					ApplicationLayer.ICMPRoutingIndex++;
					updateGUIICMPTable();
					byte[] src_iden = ApplicationLayer
							.Int2byte((ApplicationLayer.ICMPRoutingTable[ApplicationLayer.ICMPRoutingIndex - 1])
									.getTransitionIdentifier());
					System.out.print("foward packet : IN-OUT");
					sendICMP(data, outside_ip, src_iden, dst_ip, ip_header_data);

				} else {
					byte[] src_iden = ApplicationLayer
							.Int2byte((ApplicationLayer.ICMPRoutingTable[pos]).getTransitionIdentifier());
					System.out.print("foward packet : IN-OUT");
					sendICMP(data, outside_ip, src_iden, dst_ip, ip_header_data);
				}
			}
		}
	}

	int get_defaul_port() {
		return (ApplicationLayer.ICMPRoutingTable[ApplicationLayer.ICMPRoutingIndex - 1].getTransitionIdentifier()) + 1;
	}

	void sendICMP(byte[] data, byte[] src, byte[] identifier, byte[] destination_ip, byte[] ip_header_data) {
//		short length_of_icmp_data = (short) (data.length + ICMP_HEAD_SIZE);
//		icmp_data = new byte[data.length + ICMP_HEAD_SIZE];
		icmp_data = new byte[data.length];
		System.arraycopy(data, 0, icmp_data, 0, icmp_data.length);

//		icmp_data[0] = 0; // type 반향응답

//		icmp_data[1] = 0; // code

		icmp_data[2] = 0;// ICMP_checksum[0];
		icmp_data[3] = 0;// ICMP_checksum[1]; //
							// checksum---------------------------------------------------

		icmp_data[4] = identifier[0];
		icmp_data[5] = identifier[1];

		TCPchecksum icmpChecksum = new TCPchecksum();
		byte[] ICMPheader = new byte[ICMP_HEAD_SIZE];
		byte[] payload = new byte[icmp_data.length - ICMP_HEAD_SIZE];
		System.arraycopy(icmp_data, 0, ICMPheader, 0, ICMPheader.length);
		System.arraycopy(icmp_data, ICMP_HEAD_SIZE, payload, 0, icmp_data.length - ICMP_HEAD_SIZE);

		byte[] checksum = icmpChecksum.generateICMPChecksum(ICMPheader, payload);

		icmp_data[2] = checksum[0];
		icmp_data[3] = checksum[1];

//		icmp_data[6] = ICMP_sequence[0];
//		icmp_data[7] = ICMP_sequence[1]; // squence number-----------------------------------------------

//		for (int i = 0; i < data.length; i++)
//			icmp_data[i + ICMP_HEAD_SIZE] = data[i];

		((IPLayer) this.getUnderLayer()).otherIPLayer.sendIPicmp(icmp_data, src, destination_ip, ip_header_data);
	}

	public void setMapTable(int index) {
		ApplicationLayer.ICMP_periodicTimer.put(index, new Timer());
	}

	class PeriodicHandler extends TimerTask {
		private ICMPLayer icmp;
		private int table_index;

		public PeriodicHandler(ICMPLayer icmp, int table_index) {
			this.icmp = icmp;
			this.table_index = table_index;
		}

		public void run() {
			System.out.println("ICMP Routing entry deleted for: " + table_index);
			ApplicationLayer.ICMPRoutingTable[table_index] = null;
			icmp.shiftRoutingTable(table_index);
			updateGUIICMPTable();
		}
	}

	public void startPeriodicTimer(int table_index) {
		PeriodicHandler task = new PeriodicHandler(this, table_index);
		ApplicationLayer.ICMP_periodicTimer.get(table_index).schedule(task, 30000);
	}

	public void shiftRoutingTable(int index) {
		for (int i = 0; i < ApplicationLayer.ICMPRoutingIndex; i++) {
			if (i >= index) {
				ApplicationLayer.ICMPRoutingTable[i] = ApplicationLayer.ICMPRoutingTable[i + 1];
			}
		}
		ApplicationLayer.ICMPRoutingIndex--;
	}

	void updateGUIICMPTable() {
		ApplicationLayer.ICMPlist.removeAll();
		for (int i = 0; i < ApplicationLayer.ICMPRoutingIndex; i++) {
			byte[] ICMP_inside_IP = ApplicationLayer.ICMPRoutingTable[i].getInside();
			int ICMP_identifier = ApplicationLayer.ICMPRoutingTable[i].getIndentifier();
			byte[] ICMP_outside_IP = ApplicationLayer.ICMPRoutingTable[i].getOutside();
			int ICMP_transition_identifier = ApplicationLayer.ICMPRoutingTable[i].getTransitionIdentifier();

			ApplicationLayer.ICMPlist.add(ApplicationLayer.byte2IP(ICMP_inside_IP) + "      " + ICMP_identifier + "   "
					+ ApplicationLayer.byte2IP(ICMP_outside_IP) + "   " + ICMP_transition_identifier);
		}
	}

}