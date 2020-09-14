package Router;

import java.util.Arrays;

public class UDPLayer extends BaseLayer {
   final static int UDP_HEAD_SIZE = 8;
//   final static int UDP_MAX_SIZE = 65535;

   byte[] udp_head;
   byte[] udp_source_port_number;//2byte
   byte[] udp_destination_port_number;//2byte
   
//   byte[] udp_len; //2byte
//   byte[] udp_checksum;//2byte
   byte[] udp_data;//header+payload

   void resetHeader() {
      udp_head = new byte[UDP_HEAD_SIZE];
      udp_source_port_number = new byte[2];
      udp_destination_port_number = new byte[2];
//      udp_len = new byte[2];
//      udp_checksum = new byte[2];
//      udp_data = new byte[UDP_MAX_SIZE];
   }

   public UDPLayer(String layerName) {
      super(layerName);
      resetHeader();
   }

//   void set_source_port_number(byte[] source_port_number) {
//      for (int i = 0; i < 2; i++) {
//         udp_source_port_number[i] = source_port_number[i];
//         udp_data[i] = source_port_number[i];
//      }
//   }
//
//   void set_destination_port_number(byte[] destination_port_number) {
//      for (int i = 0; i < 2; i++) {
//         udp_destination_port_number[i] = udp_source_port_number[i];
//         udp_data[i + 2] = destination_port_number[i];
//      }
//   }
//
//   public static int byte2Int(byte[] src) {
//      int s1 = src[0] & 0xFF;
//      int s2 = src[1] & 0xFF;
//
//      return ((s1 << 8) + (s2 << 0));
//   }

   void receiveUDP(byte[] data, byte[] destination, byte[] source) {
      byte[] protocol = new byte[2];
      
      //get dst port : should be 0x0208
      protocol[0] = data[2];
      protocol[1] = data[3];

      if (protocol[0] == 0x02 && protocol[1] == 0x08) {
         //System.out.println(">UDP HEADER PROTOCOL IS RIP MESSAGE");
         byte[] decapsulation = Arrays.copyOfRange(data, UDP_HEAD_SIZE, data.length);
         ((RIPLayer) this.getUpperLayer()).RIP_received(decapsulation);
      } else {
         //System.out.println(">>NOT RIP MESSAGE");
      }
   }

   void sendRIP(byte[] data) { // rip瑜� 蹂대궡�뒗 �븿�닔
      //System.out.println(">>SEND RIP MESSAGE : ");
      short length_of_udp_data = (short) (data.length+UDP_HEAD_SIZE);
      
      //udp data = udp header + udp payload(data)
      udp_data = new byte[data.length + UDP_HEAD_SIZE]; 
      
      //rip port : set src/dst port number to 520 -> 0x0208 
      udp_source_port_number[0] = 0x02;
      udp_source_port_number[1] = 0x08;
      
      udp_destination_port_number[0] = 0x02;
      udp_destination_port_number[1] = 0x08;
      
      //src port
      udp_data[0]=udp_source_port_number[0];
      udp_data[1]=udp_source_port_number[1];
      
      //dst port
      udp_data[2]=udp_destination_port_number[0];
      udp_data[3]=udp_destination_port_number[1];
      
      //length -> int to byte conversion needed
      udp_data[4]= (byte) ((length_of_udp_data>>8) & 0xff);
      udp_data[5]= (byte) (length_of_udp_data & 0xff);
            
      //checksum field filled later
      udp_data[6]=0x00;
      udp_data[7]=0x00;
      
      //payload added to udp_data
      for (int i = 0; i < data.length; i++) // udp header 異붽�
         udp_data[i + UDP_HEAD_SIZE] = data[i];

      ((IPLayer) this.getUnderLayer()).sendIP(udp_data);
   }
}