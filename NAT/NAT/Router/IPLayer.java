package Router;

import java.util.Arrays;

public class IPLayer extends BaseLayer {
	final static int IP_HEAD_SIZE = 20;
//   final static int IP_MAX_SIZE = 65535;
	byte[] ip_head = new byte[IP_HEAD_SIZE];
	byte[] ip_sourceIP = new byte[4];
	byte[] ip_destinationIP = new byte[4];
//   byte[] ip_totallen = new byte[2];
//   byte[] ip_checksum = new byte[2];
	byte[] ip_data;
//   byte[] ip_TTL;
//   byte[] ip_type_plus_service;
	int interfaceNumber;

	IPLayer otherIPLayer;

	RoutingTable[] routingTable;

	public IPLayer(String layerName) {
		super(layerName);
	}

	void setOtherIPLayer(IPLayer other) {
		otherIPLayer = other;
	}

	void setInterfaceNumber(int number) {
		interfaceNumber = number;
	}

	void setRoutingTable(RoutingTable[] routingTable) {
		this.routingTable = routingTable;
	}


	void setSourceIpAddress(byte[] sourceAddress) {
		for (int i = 0; i < 4; i++) {
			ip_sourceIP[i] = sourceAddress[i];
//         ip_data[i + 12] = sourceAddress[i];
		}
	}

	void setDestinationIPAddress(byte[] destinationAddress) {
		for (int i = 0; i < 4; i++) {
			ip_destinationIP[i] = destinationAddress[i];
//         ip_data[i + 16] = destinationAddress[i];
		}
	}

	boolean receiveIP(byte[] data) {
		// ip_data = header+payload
		ip_data = new byte[data.length];
		System.arraycopy(data, 0, ip_data, 0, data.length);

		byte[] ip_header_data = Arrays.copyOfRange(ip_data, 0, IP_HEAD_SIZE);
		byte[] payload = Arrays.copyOfRange(ip_data, IP_HEAD_SIZE, ip_data.length);

		byte[] frame_dst_ip = new byte[4];
		System.arraycopy(ip_header_data, 16, frame_dst_ip, 0, 4);
//		frame_dst_ip[0] = ip_header_data[16];
//		frame_dst_ip[1] = ip_header_data[17];
//		frame_dst_ip[2] = ip_header_data[18];
//		frame_dst_ip[3] = ip_header_data[19];

		byte[] frame_src_ip = new byte[4];
		System.arraycopy(ip_header_data, 12, frame_src_ip, 0, 4);
//		frame_src_ip[0] = ip_header_data[12];
//		frame_src_ip[1] = ip_header_data[13];
//		frame_src_ip[2] = ip_header_data[14];
//		frame_src_ip[3] = ip_header_data[15];

		int check = 0;

		// System.out.println(">>[SRC IP] " + ApplicationLayer.byte2IP(frame_src_ip));
		// System.out.println(">>[DST IP] " + ApplicationLayer.byte2IP(frame_dst_ip));

//      if (java.util.Arrays.equals(frame_dst_ip, ip_sourceIP)) { // do we need to compare??
		// System.out.println(">>IP HEADER PROTOCOL : " + ip_data[9]);
		if (this.interfaceNumber == 0 || (this.interfaceNumber == 1 && Arrays.equals(frame_dst_ip, ip_sourceIP))) {
			// 외부에서 int1로 들어온 경우
			if (ip_data[9] == 0x01) {
				((ICMPLayer) this.getOtherUpperLayer()).ICMP_received(payload, frame_dst_ip, frame_src_ip, ip_header_data);
				System.out.println(">>IP HEADER PROTOCOL IS ICMP");
			} else if (ip_data[9] == 0x06) {
//				System.out.println(">>IP HEADER PROTOCOL IS TCP");
				if (ApplicationLayer.byte2IP(frame_dst_ip).equals("216.58.203.46")) {
					System.out.println("GOOGLE CONNECT REQEUST");
				}
				else if(ApplicationLayer.byte2IP(frame_src_ip).equals("216.58.203.46")) {
					System.out.println("FROM GOOGLE");
				}
				System.out.println("--------------------------------------------START ANALYSIS--------------------------------------------------");
				((TCPLayer) this.getUpperLayer()).receiveTCP(payload, frame_dst_ip, frame_src_ip, ip_header_data);
			} else {
//				System.out.println(">>IP HEADER PROTOCOL IS NOT ICMP & TCP");
				for (int i = 0; i < ApplicationLayer.routingIndex; i++) {
					byte[] destination = ApplicationLayer.routingTable[i].getDestination();
					for (int j = 0; j < 4; j++) {
						byte[] netMask = ApplicationLayer.routingTable[i].getNetMask();
						if (destination[j] != (netMask[j] & frame_dst_ip[j])) {
							check = 0;
							break;
						} else
							check = 1;
					}
					if (check == 1) {
						if (interfaceNumber == ApplicationLayer.routingTable[i].getInterface()) {
							((ARPLayer) this.getUnderLayer()).send(ip_data,
									ApplicationLayer.routingTable[i].getGateway());
						} else {
							((ARPLayer) otherIPLayer.getUnderLayer()).send(ip_data,
									ApplicationLayer.routingTable[i].getGateway());
						}
						return true;
					}
				}
			}

		}
		return false;
	}

	byte[] getPublicIP() {
		return otherIPLayer.ip_sourceIP;
	}
	
	boolean sendIPicmp(byte[] data, byte[] src, byte[] dst, byte[] ip_header_data) {
		short length_of_ip_data = (short) (data.length + IP_HEAD_SIZE);

		// ip data = ip header + payload
		ip_data = new byte[data.length + IP_HEAD_SIZE];

		int check = 0;

		ip_data[0] = (byte) 0x45; // version:4 & header length:5
		ip_data[1] = (byte) 0x00; // TOS
		ip_data[2] = (byte) ((length_of_ip_data >> 8) & 0xff); // length
		ip_data[3] = (byte) (length_of_ip_data & 0xff); // length
//      ip_data[4]=;
//      ip_data[5]=;
//      ip_data[6]=;
//      ip_data[7]=;
		ip_data[8] = (byte) 0xFF; // TTL:255
		ip_data[9] = (byte) 0x01; // protocol:17

		for (int i = 0; i < ip_header_data.length; i++) {
			ip_data[i] = ip_header_data[i];
		}

		ip_data[10] = (byte) 0x00;// checksum
		ip_data[11] = (byte) 0x00;// checksum

		// src address
		ip_data[12] = src[0];
		ip_data[13] = src[1];
		ip_data[14] = src[2];
		ip_data[15] = src[3];

		// -> get it from arp cache table
		ip_data[16] = dst[0];
		ip_data[17] = dst[1];
		ip_data[18] = dst[2];
		ip_data[19] = dst[3];

		System.arraycopy(ip_data, 0, ip_header_data, 0, ip_header_data.length);
		
		
		TCPchecksum ipChecksum = new TCPchecksum();
		byte[] checksum = ipChecksum.generateIPchecksum(ip_header_data);

		ip_data[10] = checksum[0];// checksum
		ip_data[11] = checksum[1];// checksum
		
		for (int i = 0; i < data.length; i++) {
			ip_data[i + IP_HEAD_SIZE] = data[i];
		}


		this.setDestinationIPAddress(dst);
		System.out.println(" packet fowarded : src : "+ApplicationLayer.byte2IP(src)+" dst:"+ApplicationLayer.byte2IP(dst));
		((ARPLayer) this.getUnderLayer()).send(ip_data, dst);
		return false;
	}
	
	boolean sendIP(byte[] data, byte[] src, byte[] dst, byte[] ip_header_data) {
//		short length_of_ip_data = (short) (data.length + IP_HEAD_SIZE);

		// ip data = ip header + payload
		ip_data = new byte[data.length + IP_HEAD_SIZE];

//		int check = 0;

//		ip_data[0] = (byte) 0x45; // version:4 & header length:5
//		ip_data[1] = (byte) 0x00; // TOS
//		ip_data[2] = (byte) ((length_of_ip_data >> 8) & 0xff); // length
//		ip_data[3] = (byte) (length_of_ip_data & 0xff); // length
////      ip_data[4]=;
////      ip_data[5]=;
////      ip_data[6]=;
////      ip_data[7]=;
//		ip_data[8] = (byte) 0xFF; // TTL:255
//		ip_data[9] = (byte) 0x06; // protocol:17

		for (int i = 0; i < ip_header_data.length; i++) {
			ip_data[i] = ip_header_data[i];
		}

		ip_data[10] = (byte) 0x00;// checksum
		ip_data[11] = (byte) 0x00;// checksum

		// src address
		ip_data[12] = src[0];
		ip_data[13] = src[1];
		ip_data[14] = src[2];
		ip_data[15] = src[3];

		// -> get it from arp cache table
		ip_data[16] = dst[0];
		ip_data[17] = dst[1];
		ip_data[18] = dst[2];
		ip_data[19] = dst[3];

		System.arraycopy(ip_data, 0, ip_header_data, 0, ip_header_data.length);
		
		
		TCPchecksum ipChecksum = new TCPchecksum();
		byte[] checksum = ipChecksum.generateIPchecksum(ip_header_data);

		ip_data[10] = checksum[0];// checksum--------------------------------------------------
		ip_data[11] = checksum[1];// checksum--------------------------------------------------
		
		for (int i = 0; i < data.length; i++) {
			ip_data[i + IP_HEAD_SIZE] = data[i];
		}

		this.setDestinationIPAddress(dst);
		
		byte[] src_port = new byte[2];
		byte[] dst_port = new byte[2];
		
		System.arraycopy(ip_data, 20, src_port, 0, src_port.length);
		System.arraycopy(ip_data, 22, dst_port, 0, dst_port.length);
		
		int SRC_PORT = byte2Int(src_port);
		int DST_PORT = byte2Int(dst_port);
		
		System.out.println("src_ip: " + ApplicationLayer.byte2IP(src) + " src_port: " + SRC_PORT
				+ "/ dst_ip: " + ApplicationLayer.byte2IP(dst) + " dst_port" + DST_PORT);
		
		System.out.println("--------------------------------------------END ANALYSIS--------------------------------------------------");
		System.out.println();
		((ARPLayer) this.getUnderLayer()).send(ip_data, dst);
		return false;
	}
	
	public static int byte2Int(byte[] src) {
		int s1 = src[0] & 0xFF;
		int s2 = src[1] & 0xFF;

		return ((s1 << 8) + (s2 << 0));
	}

	boolean receiveARP(byte[] data) {
		int check = 1;
		byte[] dst_ip = new byte[4];
		System.arraycopy(data, 24, dst_ip, 0, 4);
		for (int i = 0; i < 4; i++) {
			// 자기 아이피 주소와 확인하는 반복문
//			System.out.println("NOW : "+ApplicationLayer.byte2IP(dst_ip));
			if (ip_sourceIP[i] != data[i + 24]) {
				check = 0;
				break;
			}
		}
		if (check == 1) {
			// ARP REQUEST가 나한테 온경우
			((ARPLayer) this.getUnderLayer()).ARP_reply_send(data);
			return true;
		}
		// ARP REQUEST가 나한테 온게 아닌 경우
		check = 0;
		for (int i = 0; i < ApplicationLayer.routingIndex; i++) {
			byte[] destination = ApplicationLayer.routingTable[i].getDestination();
			for (int j = 0; j < 4; j++) {
				byte[] netMask = ApplicationLayer.routingTable[i].getNetMask();
				if (destination[j] != (netMask[j] & data[j + 24])) {
					check = 0;
					break;
				} else
					check = 1;
			}
			if (check == 1) {
				if (interfaceNumber != ApplicationLayer.routingTable[i].getInterface()) {
					((ARPLayer) this.getUnderLayer()).ARP_reply_send(data);
					((ARPLayer) otherIPLayer.getUnderLayer())
							.ARP_request_send(ApplicationLayer.routingTable[i].getGateway());
				} else {
					((ARPLayer) this.getUnderLayer()).ARP_reply_send(data);
				}
				return true;
			}
		}
		((ARPLayer) this.getUnderLayer()).ARP_reply_send(data);
		return false;
	}
}