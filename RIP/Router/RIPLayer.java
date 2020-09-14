package Router;

import java.util.ArrayList;
import java.util.Timer;
import java.util.TimerTask;

public class RIPLayer extends BaseLayer {
   int RIP_MAX_SIZE;
   static int PERIODIC_TIMER_INTERVAL = 5000; // 30초 (기본 값)
   static int TIMEOUT_INTERVAL = PERIODIC_TIMER_INTERVAL * 6; // 180초
   static int GARBAGE_INTERVAL = PERIODIC_TIMER_INTERVAL * 4; // 120초

   byte[] RIP_command; // Request면 1, Reply면 2
   byte[] RIP_version; // 1 or 2?
   byte[] RIP_addressFamily; // 주소형식 정의하기 위해 서용. IP주소를 사용하므로 2로 설정
   byte[] RIP_routeTag; // 내부 경로인지 외부 경로인지 구분하는 방법 (RIPv1은 null, RIPv2는 EGP나 BGP의 AS번호)
   byte[] RIP_ipAddr; // 라우팅 테이블의 네트워크 목적지주소
   byte[] RIP_subNetMask; // 0이면 그 엔트리를 위한 서브넷마스크가 존재하지 않음 (RIPv1은 null, RIPv2는 Subnet mask)
   byte[] RIP_nextHopIpAddr; // 패킷이 포워딩 되기 위해 다음 지점의 IP주소를 나타냄 (RIPv1은 null, RIPv2는 Next-Hop IP주소)

   byte[] ip_sourceIP = new byte[4];

   final int INFINITY = 16;
   int metric; // 홉수
   int interfaceNumber;
//   RoutingTable[] routingTable; // 라우팅 테이블 클래스에 있는 라우팅테이블 가져오기

   public RIPLayer(String layerName) {
      super(layerName);
      resetRIP();
   } // RIP레이어 생성자

   void setInterfaceNumber(int number) {
      interfaceNumber = number;
   }

   void setRoutingTable(RoutingTable[] routingTable) {
//      this.routingTable = routingTable;
   } // 라우팅테이블 설정자 메소드

   void setSourceIpAddress(byte[] sourceAddress) {
      for (int i = 0; i < 4; i++) {
         ip_sourceIP[i] = sourceAddress[i];
      }
   }

   void setMetric(int number) {
      metric = number;
   } // metric를 설정하는 메소드

   public void resetRIP() {
      RIP_command = new byte[1];
      RIP_command[0] = 0x01;
      RIP_version = new byte[1];
      RIP_version[0] = 0x02; // 버전 2
      RIP_addressFamily = new byte[2];
      RIP_addressFamily[0] = 0x00;
      RIP_addressFamily[1] = 0x02; // IP주소 사용하므로 2
      RIP_routeTag = new byte[2];
      RIP_routeTag[0] = 0x00;
      RIP_routeTag[1] = 0x01;

      RIP_ipAddr = new byte[4];
      RIP_subNetMask = new byte[4];
      RIP_nextHopIpAddr = new byte[4];
   }

   public void setMapTable(int index) {
      ApplicationLayer.timeoutTimers.put(index, new Timer());
      ApplicationLayer.garbageTimers.put(index, new Timer());
   }

   void updateGUIRoutingTable() {
      ApplicationLayer.StaticRoutingList.removeAll();
      for (int i = 0; i < ApplicationLayer.routingIndex; i++) {
         byte[] tempDestination = ApplicationLayer.routingTable[i].getDestination();
         byte[] tempNetmask = ApplicationLayer.routingTable[i].getNetMask();
         byte[] tempGateway = ApplicationLayer.routingTable[i].getGateway();
         Flag tempFlag = ApplicationLayer.routingTable[i].getFlag();
         int temp_metric = ApplicationLayer.routingTable[i].getMetric();
         int temp_interface = ApplicationLayer.routingTable[i].getInterface();
         ApplicationLayer.StaticRoutingList.add(ApplicationLayer.byte2IP(tempDestination) + "  "
               + ApplicationLayer.byte2IP(tempNetmask) + "  " + ApplicationLayer.byte2IP(tempGateway) + "  "
               + tempFlag + "  " + temp_interface + "  " + temp_metric);
      }
   }

   class PeriodicHandler extends TimerTask {
      private RIPLayer rip;

      public PeriodicHandler(RIPLayer rip) {
         this.rip = rip;
      }

      public void run() {
         // TODO:: Send Periodic signal
//         System.out.println("Timer starts");
         RIP_request_send();
      }
   }

   class TimeoutHandler extends TimerTask {

      private RIPLayer rip;
      private int table_index;

      public TimeoutHandler(RIPLayer rip, int table_index) {
         this.rip = rip;
         this.table_index = table_index;
      }

      public void run() {
         synchronized (ApplicationLayer.routingTable) {
            // garbage collection 시작
            System.out.println("Timeout completed for: " + table_index);
            startGarbageCollection(table_index); // GarbageCollection 시작
            ApplicationLayer.routingTable[table_index].setMetric(INFINITY); // 해당 entry Hop = 16

            System.out.println("------------------------ routing table After Timeout ----------------------------");
            for (int i = 0; i < ApplicationLayer.routingIndex; i++) {
               System.out.print(">>[" + ApplicationLayer.routingTable[i].getIndex() + "][DST]"
                     + ApplicationLayer.byte2IP(ApplicationLayer.routingTable[i].getDestination()));
               System.out.print(
                     ">>[NETMASK]" + ApplicationLayer.byte2IP(ApplicationLayer.routingTable[i].getNetMask()));
               System.out.print(
                     ">>[GATEWAY]" + ApplicationLayer.byte2IP(ApplicationLayer.routingTable[i].getGateway()));
               System.out.print(">>[INF]" + ApplicationLayer.routingTable[i].getInterface());
               System.out.println(">>[METRIC]" + ApplicationLayer.routingTable[i].getMetric());
               System.out.println();
            }
            System.out.println("--------------------------------------------------------------------------------");
            updateGUIRoutingTable();
         }
      }
   }

   class GarbargeHandler extends TimerTask {

      private RIPLayer rip;
      private int table_index;

      public GarbargeHandler(RIPLayer rip, int table_index) {
         this.rip = rip;
         this.table_index = table_index;
      }

      public void run() {
         synchronized (ApplicationLayer.routingTable) { // routingTable 변경사항 동기화
            // TODO:: Routing Table에서 해당 router 삭제
            System.out.println("Routing entry deleted for: " + table_index);
            ApplicationLayer.routingTable[table_index] = null; // 테이블에서 삭제
            rip.shiftRoutingTable(table_index); // routingTable
            ApplicationLayer.timeoutTimers.get(table_index).cancel(); // TimeoutTimer 삭제

            System.out.println("------------------------ routing table After Garbage ----------------------------");
            for (int i = 0; i < ApplicationLayer.routingIndex; i++) {
               System.out.print(">>[" + ApplicationLayer.routingTable[i].getIndex() + "][DST]"
                     + ApplicationLayer.byte2IP(ApplicationLayer.routingTable[i].getDestination()));
               System.out.print(
                     ">>[NETMASK]" + ApplicationLayer.byte2IP(ApplicationLayer.routingTable[i].getNetMask()));
               System.out.print(
                     ">>[GATEWAY]" + ApplicationLayer.byte2IP(ApplicationLayer.routingTable[i].getGateway()));
               System.out.print(">>[INF]" + ApplicationLayer.routingTable[i].getInterface());
               System.out.println(">>[METRIC]" + ApplicationLayer.routingTable[i].getMetric());
               System.out.println();
            }
            System.out.println("--------------------------------------------------------------------------------");
            updateGUIRoutingTable();
         }
      }
   }

   public void startPeriodicTimer() {
      Timer periodicTimer = new Timer();
      PeriodicHandler task = new PeriodicHandler(this);
      periodicTimer.scheduleAtFixedRate(task, 0, PERIODIC_TIMER_INTERVAL); // 30초마다 task 실행
   }

   public void setTimeoutTimer(int table_index) {
      System.out.println("TimeoutTimer Called!!!   INDEX: " + table_index);
      ApplicationLayer.timeoutTimers.get(table_index).cancel(); // TimeoutTimer 삭제
      ApplicationLayer.garbageTimers.get(table_index).cancel(); // garbageTimer 삭제
      ApplicationLayer.timeoutTimers.replace(table_index, new Timer()); // Timer 초기화
      ApplicationLayer.garbageTimers.replace(table_index, new Timer()); // Timer 초기화
      TimeoutHandler task = new TimeoutHandler(this, table_index);
      ApplicationLayer.timeoutTimers.get(table_index).schedule(task, TIMEOUT_INTERVAL);
   }

   public void startGarbageCollection(int table_index) {
      System.out.println("Garbage Collection Called!!!    INDEX: " + table_index);
      ApplicationLayer.garbageTimers.get(table_index).cancel(); // garbageTimer 삭제
      ApplicationLayer.garbageTimers.replace(table_index, new Timer()); // Timer 초기화
      GarbargeHandler task = new GarbargeHandler(this, table_index);
      ApplicationLayer.garbageTimers.get(table_index).schedule(task, GARBAGE_INTERVAL);
   }

   public void shiftRoutingTable(int index) {
      for (int i = 0; i < ApplicationLayer.routingIndex; i++) {
         if (i >= index) {
            ApplicationLayer.routingTable[i] = ApplicationLayer.routingTable[i + 1];
         }
      }
      ApplicationLayer.routingIndex--;
   }

   void RIP_received(byte[] data) {
//      System.out.println(">>RIP RECEIVED");
      byte command = data[0];
      if (command == 0x01) {
         this.RIP_request_received();
      } else {
         this.RIP_response_received(data);
      }
   }

   void RIP_request_send() { // RIP 요청 패킷 - 30초 마다 실행
      // rip 헤더 만들기 4 byte
      System.out.println("RIP REQUEST SEND / CURRENT NO ROUTING ENTRIES : " + ApplicationLayer.routingIndex);
      RIP_command[0] = 0x01;// request일때

      // rip 메세지 크기 : 20byte * 엔트리 수 + 4byte
      int rip_max_size = 4 + 20 * ApplicationLayer.routingIndex;
      byte[] rip_data = new byte[rip_max_size];

      // rip format header
      rip_data[0] = RIP_command[0];
      rip_data[1] = RIP_version[0];
      rip_data[2] = 0;
      rip_data[3] = 0;
      rip_data[4] = RIP_addressFamily[0];
      rip_data[5] = RIP_addressFamily[1];
      rip_data[6] = RIP_routeTag[0];
      rip_data[7] = RIP_routeTag[1];

      ((UDPLayer) this.getUnderLayer()).sendRIP(rip_data);
   }

   void RIP_request_received() {
//      System.out.println(">>RIP REQUEST RECEIVED");
      this.RIP_response_send();
   }

   void RIP_response_received(byte[] data) {
//      System.out.println(">>RIP RESPONSE RECEIVED");
      this.RIP_update(data);
   }

   void RIP_response_send() {
      System.out.println(">>RIP RESPONSE SEND / CURRENT NO ROUTING ENTRIES : " + ApplicationLayer.routingIndex);
      // rip 헤더 만들기 4 byte
      RIP_command[0] = 0x02;// response일때

      // rip 메세지 크기 : 20byte * 엔트리 수 + 4byte
      int rip_max_size = 4 + 20 * ApplicationLayer.routingIndex;
      byte[] rip_data = new byte[rip_max_size];

      // rip format header
      rip_data[0] = RIP_command[0];
      rip_data[1] = RIP_version[0];
      rip_data[2] = 0;
      rip_data[3] = 0;

      // 라우팅 테이블 돌면서 모든 엔트리를 rip 메세지화 20byte * 엔트리 수
      int locNextMessage = 4;
      for (int i = 0; i < ApplicationLayer.routingIndex; i++) {
         RIP_ipAddr = ApplicationLayer.routingTable[i].getDestination();
         RIP_subNetMask = ApplicationLayer.routingTable[i].getNetMask();
         RIP_nextHopIpAddr = this.ip_sourceIP;

         // Poison reverse : 만약 같은 인터페이스로 들어오고 나가면 +1 이 아닌 16으로 홉수를 변결
         // 내 인터페이스 번호를 알아야하고, 라우팅 테이블의 엔트리의 인터페이스 번호와 비교해서 같으면 16, 다르면 +1
         if (interfaceNumber == ApplicationLayer.routingTable[i].getInterface()) {
            this.metric = 16;
         } else {
            this.metric = ApplicationLayer.routingTable[i].getMetric();
         }

         System.arraycopy(RIP_addressFamily, 0, rip_data, locNextMessage, 2);// 4
         System.arraycopy(RIP_routeTag, 0, rip_data, locNextMessage + 2, 2);// 6
         System.arraycopy(RIP_ipAddr, 0, rip_data, locNextMessage + 4, 4);// 8
         System.arraycopy(RIP_subNetMask, 0, rip_data, locNextMessage + 8, 4);// 12
         System.arraycopy(RIP_nextHopIpAddr, 0, rip_data, locNextMessage + 12, 4);// 16
         rip_data[locNextMessage + 16] = (byte) (this.metric >> 24 & 0xff);
         rip_data[locNextMessage + 17] = (byte) (this.metric >> 16 & 0xff);
         rip_data[locNextMessage + 18] = (byte) (this.metric >> 8 & 0xff);
         rip_data[locNextMessage + 19] = (byte) (this.metric & 0xff);

         locNextMessage += 20;
      }
      ((UDPLayer) this.getUnderLayer()).sendRIP(rip_data);
   }

   void RIP_triggered_response(ArrayList<Integer> indexArray) { // RIP 요청 패킷
//      System.out.println(">>RIP TRIGGERED RESPONSE / NUMBER OF TRIGGERED ENTRIES : " + indexArray.size());
      // rip 헤더 만들기 4 byte
      RIP_command[0] = 0x02;// response일때

      // rip 메세지 크기 : 20byte * 엔트리 수 + 4byte
      int rip_max_size = 4 + 20 * indexArray.size();
      byte[] rip_data = new byte[rip_max_size];

      // rip format header
      rip_data[0] = RIP_command[0];
      rip_data[1] = RIP_version[0];
      rip_data[2] = 0;
      rip_data[3] = 0;

      // 라우팅 테이블 돌면서 모든 엔트리를 rip 메세지화 20byte * 엔트리 수
      int locNextMessage = 4;
      for (int i : indexArray) {
         RIP_ipAddr = ApplicationLayer.routingTable[i].getDestination();
         RIP_subNetMask = ApplicationLayer.routingTable[i].getNetMask();
         RIP_nextHopIpAddr = ApplicationLayer.routingTable[i].getGateway();

         // Poison reverse : 만약 같은 인터페이스로 들어오고 나가면 +1 이 아닌 16으로 홉수를 변결
         // 내 인터페이스 번호를 알아야하고, 라우팅 테이블의 엔트리의 인터페이스 번호와 비교해서 같으면 16, 다르면 +1
         if (interfaceNumber == ApplicationLayer.routingTable[i].getInterface()) {
            this.metric = 16;
         } else {
            this.metric = ApplicationLayer.routingTable[i].getMetric();
         }

         System.arraycopy(RIP_addressFamily, 0, rip_data, locNextMessage, 2);// 4
         System.arraycopy(RIP_routeTag, 0, rip_data, locNextMessage + 2, 2);// 6
         System.arraycopy(RIP_ipAddr, 0, rip_data, locNextMessage + 4, 4);// 8
         System.arraycopy(RIP_subNetMask, 0, rip_data, locNextMessage + 8, 4);// 12
         System.arraycopy(RIP_nextHopIpAddr, 0, rip_data, locNextMessage + 12, 4);// 16
         rip_data[locNextMessage + 16] = (byte) (this.metric >> 24 & 0xff);
         rip_data[locNextMessage + 17] = (byte) (this.metric >> 16 & 0xff);
         rip_data[locNextMessage + 18] = (byte) (this.metric >> 8 & 0xff);
         rip_data[locNextMessage + 19] = (byte) (this.metric & 0xff);
         locNextMessage += 20;
      }
      ((UDPLayer) this.getUnderLayer()).sendRIP(rip_data);

   }

   void RIP_update(byte[] data) { // RIP 응답 패킷 (테이블 갱신)
      System.out.println(">>RIP UPDATING!!");
      Flag hostFlag = Flag.UH;
      byte[] receive_target_IP = new byte[4];
      byte[] next_hop_IP = new byte[4];
      byte[] net_mask = new byte[4];
      RIP_MAX_SIZE = data.length; // 들어온 데이터 크기 만큼이 최대 크기
      byte[] receive_rip_data = data; // 받은 데이터를 가지고 분석
      ArrayList<Integer> index_modified_entries = new ArrayList<Integer>();
      byte[] temp = new byte[4];
      for (int i = 4; i < RIP_MAX_SIZE; i += 20) { // RIP메시지에서 데이터크기는 20바이트이므로
         System.arraycopy(receive_rip_data, i + 4, receive_target_IP, 0, 4); // 목적지뽑아내기
         System.arraycopy(receive_rip_data, i + 8, net_mask, 0, 4); // netMask뽑아내기
         System.arraycopy(receive_rip_data, i + 12, next_hop_IP, 0, 4); // next_hop뽑아내기
         System.arraycopy(receive_rip_data, i + 16, temp, 0, 4); // metric뽑아내기

         int metric_apart = temp[3];
         System.out.println("metric_apart: " + metric_apart);
         int index = find_RoutingTable(receive_target_IP);
         int new_metric = metric_apart + 1; // metric에 1 증가시킨 값들 저장한다
         if (index == -1) { // 테이블에 없는 목적지라면
        	if(new_metric > 16) {
        		continue;
        	}
            System.out.println("테이블에 없음");
            int new_index = ApplicationLayer.routingIndex;
            // 이 위치는 null point 이기때문에 배열을 늘리고 삽입해야합
            ApplicationLayer.routingTable[new_index] = new RoutingTable();// 새로운 엔트리 생성
            ApplicationLayer.routingTable[new_index].modifyRoutingTable(receive_target_IP, net_mask, next_hop_IP,
                  Flag.UG, interfaceNumber, new_index, new_metric);
            index_modified_entries.add(new_index);
            setMapTable(new_index);
               setTimeoutTimer(new_index);
            ApplicationLayer.routingIndex++;
            // 라우팅 테이블에 추가
         } else { // 테이블에 있는 목적지라면
            System.out.println("------------------------------------------");
            System.out.println("테이블에 존재 index: " + index);
            
            if (metric_apart!=16) {
               setTimeoutTimer(index); // Timeout Timer reset! (초 재시작)
            }else if(ApplicationLayer.routingTable[index].getInterface()==this.interfaceNumber) {
               setTimeoutTimer(index); // Timeout Timer reset! (초 재시작)
            }
            
            // timeoutTimer(index);
            if (next_hop_IP == ApplicationLayer.routingTable[index].getGateway()) { // next-hop이 테이블에 게이트웨이와 같으면
               ApplicationLayer.routingTable[index].modifyRoutingTable(receive_target_IP, net_mask, next_hop_IP,
                     Flag.UG, interfaceNumber, index, new_metric);
               index_modified_entries.add(index);
               // 라우팅 테이블에 있는 게이트웨이를 next_hop_IP로 대체해줌
            } else {
               if (new_metric < ApplicationLayer.routingTable[index].getMetric()) { // metric가 테이블에 있는 metric보다 작으면
                  ApplicationLayer.routingTable[index].modifyRoutingTable(
                        ApplicationLayer.routingTable[index].getDestination(),
                        ApplicationLayer.routingTable[index].getNetMask(), next_hop_IP,
                        ApplicationLayer.routingTable[index].getFlag(),
                        ApplicationLayer.routingTable[index].getInterface(), index, new_metric);
                  index_modified_entries.add(index);
                  // 라우팅 테이블에 있는 metric를 받은 데이터의 metric으로 대체해줌
               }
            }
         } // 수정이 일어난 엔트리들의 실제 rt의 인덱스를 가져와서 그 애들만 포함하는 message를 만들어서 보내줌
      }
      if (!index_modified_entries.isEmpty()) {// triggered response가 필요한 경우
         this.RIP_triggered_response(index_modified_entries);
      }

      // gui 갱신 : 현재 gui 정보 다 삭제 후, 모든 라우팅 테이블 순회하며 갱신
      updateGUIRoutingTable();
      System.out.println("------------------------------ routing table -----------------------------------");
      for (int i = 0; i < ApplicationLayer.routingIndex; i++) {
         System.out.print(">>[" + ApplicationLayer.routingTable[i].getIndex() + "][DST]"
               + ApplicationLayer.byte2IP(ApplicationLayer.routingTable[i].getDestination()));
         System.out.print(">>[NETMASK]" + ApplicationLayer.byte2IP(ApplicationLayer.routingTable[i].getNetMask()));
         System.out.print(">>[GATEWAY]" + ApplicationLayer.byte2IP(ApplicationLayer.routingTable[i].getGateway()));
         System.out.print(">>[INF]" + ApplicationLayer.routingTable[i].getInterface());
         System.out.println(">>[METRIC]" + ApplicationLayer.routingTable[i].getMetric());
         System.out.println();
      }
      System.out.println("--------------------------------------------------------------------------------");
   }

   int find_RoutingTable(byte[] IP_address) { // 라우팅테이블에서 찾으려는 주소가 있는지 확인
      byte[] temp = new byte[4];
      for (int i = 0; i < ApplicationLayer.routingIndex; i++) {
         System.arraycopy(ApplicationLayer.routingTable[i].getDestination(), 0, temp, 0, 4);
         if (java.util.Arrays.equals(IP_address, temp)) {
            return i;
         }
      }
      return -1;
   }
}