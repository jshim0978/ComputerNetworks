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

//   RoutingTable[] routingTable;

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
//      this.routingTable = routingTable;
   }

//   void setVersion(byte[] type_plus_service) {
//      for (int i = 0; i < 2; i++) {
//         ip_data[i] = type_plus_service[i];
//      }
//   }

//   void setTotalLength(byte[] totallen) {
//      if ((totallen.length) < 256) {
//         ip_totallen[0] = (byte) (((totallen.length) & 0xFF) >> 8);
//         ip_totallen[1] = (byte) ((totallen.length) & 0xFF);
//      } else {
//         ip_totallen[0] = (byte) ((totallen.length) / 256);
//         ip_totallen[1] = (byte) ((totallen.length) % 256);
//      }
//      for (int i = 0; i < 2; i++) {
//         ip_totallen[i] = totallen[i];
//         ip_data[i + 2] = totallen[i];
//      }
//   }

//   void setTTL(byte[] TTL) {
//      ip_data[8] = TTL[0];
//   }


//   void setIpProtocol(byte[] protocol) {
//      ip_data[9] = protocol[0];
//   }

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
      frame_dst_ip[0] = ip_header_data[16];
      frame_dst_ip[1] = ip_header_data[17];
      frame_dst_ip[2] = ip_header_data[18];
      frame_dst_ip[3] = ip_header_data[19];

      byte[] frame_src_ip = new byte[4];
      frame_src_ip[0] = ip_header_data[12];
      frame_src_ip[1] = ip_header_data[13];
      frame_src_ip[2] = ip_header_data[14];
      frame_src_ip[3] = ip_header_data[15];

      int check = 0;

      //System.out.println(">>[SRC IP] " + ApplicationLayer.byte2IP(frame_src_ip));
      //System.out.println(">>[DST IP] " + ApplicationLayer.byte2IP(frame_dst_ip));

//      if (java.util.Arrays.equals(frame_dst_ip, ip_sourceIP)) { // do we need to compare??
      //System.out.println(">>IP HEADER PROTOCOL : " + ip_data[9]);
      if (ip_data[9] == 0x11) {
         //System.out.println(">>IP HEADER PROTOCOL IS UDP");
         ((UDPLayer) this.getUpperLayer()).receiveUDP(payload, frame_dst_ip, frame_src_ip);
      } else {
         //System.out.println(">>IP HEADER PROTOCOL IS NOT UDP such as 'ping'");
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
                  ((ARPLayer) this.getUnderLayer()).send(ip_data, ApplicationLayer.routingTable[i].getGateway());
               } else {
                  ((ARPLayer) otherIPLayer.getUnderLayer()).send(ip_data, ApplicationLayer.routingTable[i].getGateway());
               }
               return true;
            }
         }
      }
      return false;
//      }
//      return false;
   }

   boolean sendIP(byte[] data) {
      short length_of_ip_data = (short) (data.length+IP_HEAD_SIZE);
      
      //ip data = ip header + payload
      ip_data = new byte[data.length + IP_HEAD_SIZE]; 
      
      int check = 0;
         
      ip_data[0]=(byte) 0x45; //version:4 & header length:5
      ip_data[1]=(byte) 0x00; //TOS
      ip_data[2]=(byte) ((length_of_ip_data>>8) & 0xff); //length
      ip_data[3]=(byte) (length_of_ip_data & 0xff); //length
//      ip_data[4]=;
//      ip_data[5]=;
//      ip_data[6]=;
//      ip_data[7]=;
      ip_data[8]= (byte) 0xFF; //TTL:255
      ip_data[9]= (byte) 0x11; //protocol:17
//      ip_data[10]=;//checksum
//      ip_data[11]=;//checksum
      
      //src address
      ip_data[12]=ip_sourceIP[0];
      ip_data[13]=ip_sourceIP[1];
      ip_data[14]=ip_sourceIP[2];
      ip_data[15]=ip_sourceIP[3];
      
      // -> get it from arp cache table
//      ip_data[16]=;
//      ip_data[17]=;
//      ip_data[18]=;
//      ip_data[19]=;

      for (int i = 0; i < data.length; i++) {
         ip_data[i + IP_HEAD_SIZE] = data[i];
      }

      
      for (int i = 0; i < ApplicationLayer.routingIndex; i++) {
         byte[] destination = ApplicationLayer.routingTable[i].getDestination();
         for (int j = 0; j < 4; j++) {
            byte[] netMask = ApplicationLayer.routingTable[i].getNetMask();
            if (destination[j] != (netMask[j] & ip_sourceIP[j])) {
               /*use own src address to find dst address, 
               since gateway address means physically connected*/
               check = 0;
               break;
            } else
               check = 1;
         }
         if (check == 1) {
            //dst address : physically connected gateway
            ip_data[16]=ApplicationLayer.routingTable[i].getGateway()[0];//index 16-19
            ip_data[17]=ApplicationLayer.routingTable[i].getGateway()[1];//index 16-19
            ip_data[18]=ApplicationLayer.routingTable[i].getGateway()[2];//index 16-19
            ip_data[19]=ApplicationLayer.routingTable[i].getGateway()[3];//index 16-19
            
            //System.out.println(">>SENDING RIP MESSAGE TO PHYSICALLY CONNECTED DESTINATION");
            if (interfaceNumber == ApplicationLayer.routingTable[i].getInterface()) {
               ((ARPLayer) this.getUnderLayer()).send(ip_data, ApplicationLayer.routingTable[i].getGateway());

            } else {
               ((ARPLayer) otherIPLayer.getUnderLayer()).send(ip_data, ApplicationLayer.routingTable[i].getGateway());
            }
            return true;
         }
      }
      return false;
   }

   boolean receiveARP(byte[] data) {
      int check = 1;
      for (int i = 0; i < 4; i++) {
         if (ip_sourceIP[i] != data[i + 24]) {
            check = 0;
            break;
         }
      }
      if (check == 1) {
         ((ARPLayer) this.getUnderLayer()).ARP_reply_send(data);
         return true;
      }
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
               ((ARPLayer) otherIPLayer.getUnderLayer()).ARP_request_send(ApplicationLayer.routingTable[i].getGateway());
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