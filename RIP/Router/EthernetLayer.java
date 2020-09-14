package Router;

import java.util.Arrays;

// 데이터 전송 시:
// 	- IP Layer에서 IP header를 덧붙인 Ethernet Layer로 보냄.
// 데이터 수신 시(Incoming from other networks):
//  - Ethernet Layer에서 패킷이 올바른지 검사(Ethernet header의 ethertype 값 사용(0x0800))
//  - Ethernet header 제거 후, IP Layer로 패킷 전달.

// Ethernet layer:
// 	- 동일 네트워크 내의 네트워크 장비까지 데이터 운반.
// 	- 동일 네트워크에선 MAC주소 사용.
//  - ARP를 사용해서 next hop의 IP MAC 주소를 찾은 후에 Ethernet header를 패킷에 추가.

public class EthernetLayer extends BaseLayer {
   final static int ETHERNET_MAX_SIZE = 1514;
   final static int ETHERNET_HEAD_SIZE = 14;
   final static int ETHERNET_MAX_DATA = ETHERNET_MAX_SIZE - ETHERNET_HEAD_SIZE;

   byte[] Ethernet_type;
   byte[] Ethernet_sourceAddress;
   byte[] Ethernet_data;

   int check = 0;

   public EthernetLayer(String layerName) {
      super(layerName);
      resetHeader();
   }

   void resetHeader() {
      Ethernet_type = new byte[2];
      Ethernet_sourceAddress = new byte[6];
      Ethernet_data = new byte[ETHERNET_MAX_SIZE];
   }

 // Frame의 source address를 받아온 인자로 설정 (6 bytes)
   void setSourceAddress(byte[] sourceAddress) {
      for (int i = 0; i < 6; i++) {
         Ethernet_sourceAddress[i] = sourceAddress[i];
         Ethernet_data[i + 6] = sourceAddress[i];
      }
   }
   
// Frame의 destination address를 받아온 인자로 설정 (6 bytes)
   void setDestinationAddress(byte[] destinationAddress) {
      for (int i = 0; i < 6; i++)
         Ethernet_data[i] = destinationAddress[i];
   }
// Frame의 Type 받아온 인자로 설정 (2 bytes)
   void setFrameType(byte[] frameType) {
      for (int i = 0; i < 2; i++)
         Ethernet_data[i + 12] = frameType[i];
   }
   
// IP Layer로 부터 data를 받았을 때,
   boolean sendIP(byte[] data, byte[] destinationAddress) {
      int length = data.length;
      // Protocol type정의(IPv4의 경우 0x0800으로 세팅)
      byte[] type = { (byte) 0x08, 0x00 };
      
      // Ethernet header만큼 길이 증가
      Ethernet_data = new byte[data.length + ETHERNET_HEAD_SIZE];
      setFrameType(type);
      setSourceAddress(Ethernet_sourceAddress);
      setDestinationAddress(destinationAddress);
      
      // Ethernet header 추가
      for (int i = 0; i < length; i++)
         Ethernet_data[i + ETHERNET_HEAD_SIZE] = data[i];
      // 하위 Layer로 헤더가 추가된 Frame 전송
      if (((PacketDriverLayer) this.getUnderLayer()).send(Ethernet_data, Ethernet_data.length))
         return true;
      else
         return false;
   }
// ARP를 날림
   boolean sendARP(byte[] data) {
      int length = data.length;
      byte[] destinationAddress = new byte[6];
      // Ethernet header만큼 길이 증가
      Ethernet_data = new byte[data.length + ETHERNET_HEAD_SIZE];
      
      // Protocol type정의(IPv4의 경우 0x0800으로 세팅)
      byte[] type = { 0x08, 0x06 };
      setFrameType(type);
      setSourceAddress(Ethernet_sourceAddress);

      if (data[7] == 2) {
         for (int i = 0; i < 6; i++)
            destinationAddress[i] = data[i + 18];
         setDestinationAddress(destinationAddress);
      } else {
         for (int i = 0; i < 6; i++)
            destinationAddress[i] = (byte) 0xff;
         setDestinationAddress(destinationAddress);
      }
      
      // Ethernet header 추가
      for (int i = 0; i < length; i++)
         Ethernet_data[i + ETHERNET_HEAD_SIZE] = data[i];
      
      if (((PacketDriverLayer) this.getUnderLayer()).send(Ethernet_data, Ethernet_data.length))
         return true;
      else
         return false;
   }

 // 외부 네트워크에서 data를 receive했을 때 호출
 // IP Layer로 전송
   synchronized boolean receive(byte[] data) {
      byte[] destinationMAC = new byte[6];
      byte[] sourceMAC = new byte[6];
      byte[] broadcast = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };
      System.arraycopy(data, 0, destinationMAC, 0, 6);
      System.arraycopy(data, 6, sourceMAC, 0, 6);
      
      if (java.util.Arrays.equals(Ethernet_sourceAddress, sourceMAC))
         return false;
      if (!(java.util.Arrays.equals(broadcast, destinationMAC) || java.util.Arrays.equals(Ethernet_sourceAddress, destinationMAC)))
         return false;
      
      // Ethernet header 제거
      byte[] dataFrame = new byte[data.length - ETHERNET_HEAD_SIZE];
      dataFrame = Arrays.copyOfRange(data, ETHERNET_HEAD_SIZE, data.length);
      
      if (data[12] == 8 && data[13] == 0)
         ((IPLayer) this.getUpperLayer()).receiveIP(dataFrame);
      if (data[12] == 8 && data[13] == 6)
         ((IPLayer) this.getUpperLayer()).receiveARP(dataFrame);
      return true;
   }
}