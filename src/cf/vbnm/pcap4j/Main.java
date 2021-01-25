package cf.vbnm.pcap4j;

import cf.vbnm.pcap4j.exceptions.*;
import org.junit.Test;

public class Main {
	public static void main(String[] args) {
		AbstractWinPcap winPcap = new AbstractWinPcap() {
			@Override
			public void captureLoopCallback(byte[] pkt, int len, int tv_Sec, int tv_uSec) {
				System.out.printf("%02X:%02X:%02X:%02X:%02X:%02X->" +
								"%02X:%02X:%02X:%02X:%02X:%02X len=%d,caplen=%d\n",
						pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5],
						pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11],
						len, pkt.length);
			}
		};
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
			winPcap.openDevice(2, 13234, Constant.PCAP_OPENFLAG_PROMISCUOUS, 500);
		} catch (ArgumentsException | FindDevicesException | PcapClosedException | OpenDeviceException e) {
			e.printStackTrace();
		}
		try {
			winPcap.loopCapture(0);
		} catch (OpenDeviceException | PcapClosedException e) {
			e.printStackTrace();
		}
		try {
			Thread.sleep(15000);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		winPcap.close();
	}

	@Test
	public void test() throws Exception {

	}


}


