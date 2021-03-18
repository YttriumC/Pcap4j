package cf.vbnm.pcap4j;

import cf.vbnm.pcap4j.exceptions.*;

public class Main {
	public static void main(String[] args) {
		AbstractWinPcap winPcap = new AbstractWinPcap();
		try {
			winPcap.findDevices();
		} catch (FindDevicesException e) {
			e.printStackTrace();
		}
		String[] devs = winPcap.getDevicesList();
		for (int i = 0; i < devs.length; i++) {
			System.out.println(i + ":" + devs[i]);
		}
		try {
			winPcap.openDevice(2, 13234, PcapConstant.PCAP_OPENFLAG_PROMISCUOUS, 500);
		} catch (ArgumentsException | FindDevicesException | PcapClosedException | OpenDeviceException e) {
			e.printStackTrace();
		}
		try {
			winPcap.loopCapture(0, (cap_pkt, len, tv_Sec, tv_uSec) -> {
//				System.out.printf("%02X:%02X:%02X:%02X:%02X:%02X->" +
//								"%02X:%02X:%02X:%02X:%02X:%02X len=%d,caplen=%d\n",
//						cap_pkt[0], cap_pkt[1], cap_pkt[2], cap_pkt[3], cap_pkt[4], cap_pkt[5],
//						cap_pkt[6], cap_pkt[7], cap_pkt[8], cap_pkt[9], cap_pkt[10], cap_pkt[11],
//						len, cap_pkt.length);
				if (cap_pkt.length!=len)
					System.err.println("Incomplete packet\n-----------------------\nIncomplete packet");
			});
		} catch (OpenDeviceException | PcapClosedException e) {
			e.printStackTrace();
		}
		try {
			Thread.sleep(15000000);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		winPcap.close();
	}

}


