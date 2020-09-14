package Router;

import java.util.Arrays;
import java.util.Timer;
import java.util.TimerTask;

public class TCPLayer extends BaseLayer {
	TCPchecksum tcpChecksum = new TCPchecksum();
	final static int TCP_HEAD_SIZE = 20;
	static int DEFAULT_PORT = 50000;
	static int SRC_PORT = 0;
	static int DST_PORT = 0;

	byte[] tcp_header;
	byte[] src_port;
	byte[] dst_port;
	byte[] seq_num;
	byte[] ack_num;
	byte[] meta_data;
	byte[] window_size;
	byte[] checksum;
	byte[] urg_pointer;
	byte[] data;
	byte[] outside_ip = new byte[4];

	byte[] tcp_data;// header+payload
	byte[] service;

	void resetHeader() {
		tcp_header = new byte[TCP_HEAD_SIZE];
		src_port = new byte[2];
		dst_port = new byte[2];
		seq_num = new byte[4];
		ack_num = new byte[4];
		meta_data = new byte[2];
		window_size = new byte[2];
		checksum = new byte[2];
		urg_pointer = new byte[2];
		outside_ip = new byte[4];
	}

	public TCPLayer(String layerName) {
		super(layerName);
		resetHeader();
	}
	// public ip 정해주려고 주석 해 놓은 부분 destination 값을 바꿔야함
//   void IP2byte(byte[] destination) {
//     for (int i = 0; i < 4; i++) {
//          outside_ip[i] = ((byte) Integer
//                .parseInt(destination.substring(i * 3, (i + 1) * 3)));
//         }
//   }

	public static int byte2Int(byte[] src) {
		int s1 = src[0] & 0xFF;
		int s2 = src[1] & 0xFF;

		return ((s1 << 8) + (s2 << 0));
	}

	void receiveTCP(byte[] data, byte[] destination, byte[] source, byte[] ip_header_data) {
		
		synchronized (ApplicationLayer.NATRoutingTable) {
//			byte[] decapsulation = Arrays.copyOfRange(data, TCP_HEAD_SIZE, data.length);
			src_port[0] = data[0];
			src_port[1] = data[1];
			SRC_PORT = byte2Int(src_port);

			dst_port[0] = data[2];
			dst_port[1] = data[3];
			DST_PORT = byte2Int(dst_port);
			byte[] src_ip = new byte[4];
			src_ip[0] = source[0];
			src_ip[1] = source[1];
			src_ip[2] = source[2];
			src_ip[3] = source[3];


			if (SRC_PORT == 80) {
				byte FLAG = data[13];
				int FLAG_L = FLAG & 0X0F;
				int FLAG_H = (((FLAG >> 2) & 0X0F)>>2) & 0xFF;
				System.out.println(FLAG_H+"+"+FLAG_L);
				
				System.out.println("tcp received: src_ip: " + ApplicationLayer.byte2IP(src_ip) + " src_port: "
						+ SRC_PORT + "/ dst_ip: " + ApplicationLayer.byte2IP(destination) + " dst_port: " + DST_PORT);
				// outer to inner
				for (int i = 0; i < ApplicationLayer.NATRoutingIndex; i++) {
					if (DST_PORT == (ApplicationLayer.NATRoutingTable[i]).getTransitionPort()) {
						byte[] inner_port = ApplicationLayer
								.Int2byte(ApplicationLayer.NATRoutingTable[i].getInsidePort());

						System.out.print("foward OUT-IN :");
						
						sendTCP(data, src_ip, src_port, inner_port, (ApplicationLayer.NATRoutingTable[i]).getInside(),
								ip_header_data);
						break;
					}
				}
			} else if (DST_PORT == 80) {
				byte FLAG = data[13];
				int FLAG_L = FLAG & 0X0F;
				int FLAG_H = (((FLAG >> 2) & 0X0F)>>2) & 0xFF;
				System.out.println(FLAG_H+"+"+FLAG_L);
//				if (ApplicationLayer.byte2IP(src_ip).equals("216.58.203.46")) {
//					System.out.println("!!!!!!!!!!!!!!!!tcp received: src_ip: " + ApplicationLayer.byte2IP(src_ip)
//							+ " src_port: " + SRC_PORT + "/ dst_ip: " + ApplicationLayer.byte2IP(destination)
//							+ " dst_port: " + DST_PORT);
//				}

				System.out.println("tcp received: src_ip: " + ApplicationLayer.byte2IP(src_ip) + " src_port: "
						+ SRC_PORT + "/ dst_ip: " + ApplicationLayer.byte2IP(destination) + " dst_port: " + DST_PORT);
				// inner to outer
				byte[] outside_ip = ((IPLayer) this.getUnderLayer()).getPublicIP();
				if (ApplicationLayer.NATRoutingIndex == 0) {
					// NAT 테이블이 비었을떄
					ApplicationLayer.NATRoutingTable[0] = new NATRoutingTable();
					ApplicationLayer.NATRoutingTable[0].setNATRoutingTable(src_ip, outside_ip, SRC_PORT, DEFAULT_PORT);
					setMapTable(ApplicationLayer.NATRoutingIndex);
					startPeriodicTimer(ApplicationLayer.NATRoutingIndex);
					ApplicationLayer.NATRoutingIndex++;
					updateGUINATTable();
					printNATTable();
					byte[] transition_port = ApplicationLayer
							.Int2byte(ApplicationLayer.NATRoutingTable[0].getTransitionPort());
					System.out.print("foward IN-OUT :");
					sendTCP(data, outside_ip, transition_port, dst_port, destination, ip_header_data);
				} else {
					// NAT 테이블이 안 비었을때
					int hasBeen = 1;
					int pos = 0;
					for (int i = 0; i < ApplicationLayer.NATRoutingIndex; i++) {
						if (!Arrays.equals(src_ip, ApplicationLayer.NATRoutingTable[i].getInside())) {
							hasBeen = 0;
						} else if (Arrays.equals(src_ip, ApplicationLayer.NATRoutingTable[i].getInside())
								&& SRC_PORT != ApplicationLayer.NATRoutingTable[i].getInsidePort()) {
							hasBeen = 0;
						} else if (Arrays.equals(src_ip, ApplicationLayer.NATRoutingTable[i].getInside())
								&& SRC_PORT == ApplicationLayer.NATRoutingTable[i].getInsidePort()) {
							pos = i;
							hasBeen = 1;
							break;
						}
					}
					if (hasBeen == 0) {
						ApplicationLayer.NATRoutingTable[ApplicationLayer.NATRoutingIndex] = new NATRoutingTable();
						ApplicationLayer.NATRoutingTable[ApplicationLayer.NATRoutingIndex].setNATRoutingTable(src_ip,
								outside_ip, SRC_PORT, get_defaul_port(ApplicationLayer.NATRoutingIndex));
						setMapTable(ApplicationLayer.NATRoutingIndex);
						startPeriodicTimer(ApplicationLayer.NATRoutingIndex);
						ApplicationLayer.NATRoutingIndex++;
						updateGUINATTable();
						printNATTable();
						byte[] transition_port = ApplicationLayer
								.Int2byte(ApplicationLayer.NATRoutingTable[ApplicationLayer.NATRoutingIndex - 1]
										.getTransitionPort());
						System.out.print("foward IN-OUT :");
						sendTCP(data, outside_ip, transition_port, dst_port, destination, ip_header_data);
					} else {
						byte[] transition_port = ApplicationLayer
								.Int2byte(ApplicationLayer.NATRoutingTable[pos].getTransitionPort());
						System.out.print("foward IN-OUT :");
						sendTCP(data, outside_ip, transition_port, dst_port, destination, ip_header_data);
					}
				}
			} else {
				// drop packet : not a correct tcp connection
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

	int get_defaul_port(int index) {
		int nextPort = (ApplicationLayer.NATRoutingTable[index - 1].getTransitionPort()) + 1;
//		System.out.println("nextPort : " + nextPort);
		return nextPort;
	}

	void sendTCP(byte[] data, byte[] source_ip, byte[] srcport, byte[] dstport, byte[] destination_ip,
			byte[] ip_header_data) {
//		short length_of_tcp_data = (short) (data.length + TCP_HEAD_SIZE);

		// tcp data = tcp header + tcp payload(data)
		tcp_data = new byte[data.length];

		System.arraycopy(data, 0, tcp_data, 0, data.length);

		// src port
		tcp_data[0] = srcport[0];
		tcp_data[1] = srcport[1];

		// dst port
		tcp_data[2] = dstport[0];
		tcp_data[3] = dstport[1];

		// length -> int to byte conversion needed
//		tcp_data[4] = (byte) ((length_of_tcp_data >> 8) & 0xff);
//		tcp_data[5] = (byte) (length_of_tcp_data & 0xff);

		// payload added to tcp_data
//		for (int i = 0; i < data.length; i++) {
//			tcp_data[i + TCP_HEAD_SIZE] = data[i];
//		}
		System.out.println();
		System.out.println("checksum before :" + tcp_data[16]+" "+tcp_data[17]);
		tcp_data[16] = (byte) 0x00;
		tcp_data[17] = (byte) 0x00;

		byte[] pseudoH = new byte[12];
		System.arraycopy(source_ip, 0, pseudoH, 0, 4);// src ip
		System.arraycopy(destination_ip, 0, pseudoH, 4, 4);// dst ip

		pseudoH[8] = (byte) 0x00;// all 0s
		pseudoH[9] = (byte) 0x06;// protocol
		byte[] tcp_length = ApplicationLayer.Int2byte(tcp_data.length);
		System.arraycopy(tcp_length, 0, pseudoH, 10, 2);// tcp length

		byte[] TCPHeader = new byte[TCP_HEAD_SIZE];
		System.arraycopy(tcp_data, 0, TCPHeader, 0, TCP_HEAD_SIZE);

		byte[] payload = new byte[tcp_data.length - TCP_HEAD_SIZE];
		System.arraycopy(tcp_data, TCP_HEAD_SIZE, payload, 0, payload.length);

		byte[] checksumForTCP = this.tcpChecksum.generateTCPchecksum(pseudoH, TCPHeader, payload);
		System.out.println("checksum After :" + checksumForTCP[0]+" "+checksumForTCP[1]);
		// checksum field filled later
		tcp_data[16] = checksumForTCP[0];
		tcp_data[17] = checksumForTCP[1];

//		System.out.println("******Destination in TCP:" + destination_ip);

		((IPLayer) this.getUnderLayer()).otherIPLayer.sendIP(tcp_data, source_ip, destination_ip, ip_header_data);
	}

	public void setMapTable(int index) {
		ApplicationLayer.NAT_periodicTimer.put(index, new Timer());
	}

	class PeriodicHandler extends TimerTask {
		private TCPLayer tcp;
		private int table_index;

		public PeriodicHandler(TCPLayer tcp, int table_index) {
			this.tcp = tcp;
			this.table_index = table_index;
		}

		public void run() {
			System.out.println("Routing entry deleted for: " + table_index);
			ApplicationLayer.NATRoutingTable[table_index] = null;
			tcp.shiftRoutingTable(table_index);
			updateGUINATTable();
			// TODO:: GUI update �븘�슂
		}
	}

	public void printNATTable() {
		System.out.println("--------------------------- NAT TABLE -------------------------------------");
		for (int i = 0; i < ApplicationLayer.NATRoutingIndex; i++) {
			System.out.println(ApplicationLayer.byte2IP(ApplicationLayer.NATRoutingTable[i].getInside()) + ":"
					+ ApplicationLayer.NATRoutingTable[i].getInsidePort() + "      "
					+ ApplicationLayer.byte2IP(ApplicationLayer.NATRoutingTable[i].getOutside()) + ":"
					+ ApplicationLayer.NATRoutingTable[i].getTransitionPort());
		}
		System.out.println("---------------------------------------------------------------------");
	}

	public void startPeriodicTimer(int table_index) {
		PeriodicHandler task = new PeriodicHandler(this, table_index);
		ApplicationLayer.NAT_periodicTimer.get(table_index).schedule(task, 600000);
	}

	public void shiftRoutingTable(int index) {
		for (int i = 0; i < ApplicationLayer.NATRoutingIndex; i++) {
			if (i >= index) {
				ApplicationLayer.NATRoutingTable[i] = ApplicationLayer.NATRoutingTable[i + 1];
			}
		}
		ApplicationLayer.NATRoutingIndex--;
	}

	void updateGUINATTable() {
		ApplicationLayer.NATlist.removeAll();
		for (int i = 0; i < ApplicationLayer.NATRoutingIndex; i++) {
			byte[] NAT_inside_IP = ApplicationLayer.NATRoutingTable[i].getInside();
			int NAT_inside_Port_Num = ApplicationLayer.NATRoutingTable[i].getInsidePort();
			byte[] NAT_outside_IP = ApplicationLayer.NATRoutingTable[i].getOutside();
			int NAT_transition_Port_Num = ApplicationLayer.NATRoutingTable[i].getTransitionPort();

			ApplicationLayer.NATlist.add(ApplicationLayer.byte2IP(NAT_inside_IP) + "      " + NAT_inside_Port_Num
					+ "   " + ApplicationLayer.byte2IP(NAT_outside_IP) + "   " + NAT_transition_Port_Num);
		}
	}
}