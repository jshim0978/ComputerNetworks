package Router;

public class TCPchecksum {
	public TCPchecksum() {

	}

	public static short[] bytetoshort(byte[] bytey) {
		short[] val = new short[bytey.length/2];
		//한 쇼트 배열칸에 두개의 바이트 연결하여 저장
		for (int i = 0 ; i < bytey.length/2 ;i ++){
			
			val[i]=(short)(((bytey[2*i] & 0xFF) << 8));
			val[i]|=(short)(bytey[2*i+1]& 0xFF);
		}
		//쇼트 배열 반환
		return val;

	}

	public byte[] generateIPchecksum(byte[] IPheader) {
		long ipChecksum = 0;
		bytetoshort(IPheader);

		for (int i = 0; i < 10; i++) {
			bytetoshort(IPheader)[i] = IPheader[2 * i];
			bytetoshort(IPheader)[i] <<= 8;
			bytetoshort(IPheader)[i] |= IPheader[(2 * i) + 1];
			// System.out.println(bytetoshort(IPheader)[i] );
			ipChecksum += (bytetoshort(IPheader)[i] & 0xFFFF);
			if ((ipChecksum & 0xFFFF0000) > 0) {
				// 32비트
				// carry 발생시
				ipChecksum = (ipChecksum & 0xFFFF) + (ipChecksum >>> 16);
				// carry 뒤에더해주기
				ipChecksum -= (byte) 0x00010000;
			}
		}
		// 뒤집고 바이트로 찢어서 저장
		byte[] checksum = new byte[2];

		checksum[1] = (byte) ~(ipChecksum & 0x00FF);
		checksum[0] = (byte) ~(ipChecksum >> 8 & 0x00FF);
		// order
		return checksum;
	}

	void setIPchecksum(byte[] IPheader, byte[] checksum) {
		IPheader[10] = checksum[0];
		IPheader[11] = checksum[1];
	}

	public byte[] generateTCPchecksum(byte[] pseudoH, byte[] TCPHeader, byte[] data) {
		byte[] checksum = new byte[2];

		long longchecksum = 0;
		// 체크섬은 캐리계산을 위해 롱으로 선언
		byte[] buf = new byte[32 + data.length + 1];
		// buf에 계산해야하는 모든 배열 합체
		for (int i = 0; i < 12; i++) {
			buf[i] = pseudoH[i];
		}
		for (int i = 12; i < 32; i++) {
			buf[i] = TCPHeader[i - 12];
		}
		for (int i = 0; i < data.length; i++) {
			buf[i + 32] = data[i];
		}
		
		short[] shortBuf = bytetoshort(buf);

		for (int i = 0; i < shortBuf.length; i++) {
			shortBuf[i] = buf[2 * i];
			shortBuf[i] <<= 8;
			shortBuf[i] |= (buf[(2 * i) + 1] & 0x00FF);
			// System.out.println( bytetoshort(buf)[i] );
			longchecksum += (shortBuf[i] & 0xFFFF);
			if ((longchecksum & 0xFFFF0000) > 0) {
				// System.out.println(longchecksum);
				longchecksum++;
				// carry 발생시 1을 뒤에 더함
				longchecksum -= 0x00010000;
			}
		}
		checksum[1] = (byte) ~(longchecksum & 0x000000FF);
		checksum[0] = (byte) ~(longchecksum >> 8 & 0x000000FF);

		return checksum;
	}

	void setTCPheaderChecksum(byte[] TCPHeader, byte[] TCPchecksum) {
		// 생성한 채크섬 TCPHeader에 저장
		TCPHeader[16] = TCPchecksum[0];
		TCPHeader[17] = TCPchecksum[1];
	}

	public byte[] generateICMPChecksum(byte[] ICMPheader, byte[] data) {
		byte[] packet = new byte[8 + data.length + 1];
		byte[] checksum = new byte[2];
		long lcs = 0;
		packet[0] = ICMPheader[0];
		packet[1] = ICMPheader[1];
		packet[2] = ICMPheader[2];
		packet[3] = ICMPheader[3];
		packet[4] = ICMPheader[4];
		packet[5] = ICMPheader[5];
		packet[6] = ICMPheader[6];
		packet[7] = ICMPheader[7];

		for (int i = 0; i < data.length; i++) {

			packet[i + 8] = data[i];
		}

		bytetoshort(packet);

		for (int i = 0; i < bytetoshort(packet).length; i++) {
			bytetoshort(packet)[i] = packet[2 * i];
			bytetoshort(packet)[i] <<= 8;
			bytetoshort(packet)[i] |= packet[(2 * i) + 1];
			// System.out.println( bytetoshort(packet)[i] );
			lcs += (bytetoshort(packet)[i] & 0xFFFF);
			if ((lcs & 0xFFFF0000) > 0) {
				// System.out.println(lcs);
				lcs++;
				lcs -= 0x00010000;
				// carry 발생시 1을 뒤에 더함
			}
		}
		checksum[1] = (byte) ~(lcs & 0x000000FF);
		checksum[0] = (byte) ~(lcs >> 8 & 0x000000FF);

		return checksum;

	}

	void setICMPChecksum(byte[] ICMPheader, byte[] checksum) {

		ICMPheader[2] = checksum[0];
		ICMPheader[3] = checksum[1];
		// System.out.println( ICMPheader[2]);
		// System.out.println( ICMPheader[3]);
	}

}