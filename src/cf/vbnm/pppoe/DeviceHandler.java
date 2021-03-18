package cf.vbnm.pppoe;

import cf.vbnm.pcap4j.AbstractWinPcap;
import cf.vbnm.pcap4j.PcapConstant;
import cf.vbnm.pcap4j.PktProcessor;
import cf.vbnm.pcap4j.exceptions.ArgumentsException;
import cf.vbnm.pcap4j.exceptions.FindDevicesException;
import cf.vbnm.pcap4j.exceptions.OpenDeviceException;
import cf.vbnm.pcap4j.exceptions.PcapClosedException;

public class DeviceHandler {
	private AbstractWinPcap winPcap;

	public void doLoop(byte[] cap_pkt, int len, int tv_Sec, int tv_uSec) {

	}

	public DeviceHandler(PktProcessor sender) throws
			FindDevicesException, PcapClosedException, ArgumentsException, OpenDeviceException {
		winPcap = new AbstractWinPcap();
		winPcap.findDevices();
		String[] devList;
		devList = winPcap.getDevicesList();
		for (int i = 0; i < devList.length; i++) {
			//	Realtek PCIe GBE Family Controller
			if (devList[i].contains("PCIe GBE Family Controller")) {
				winPcap.openDevice(i, 1600, PcapConstant.PCAP_OPENFLAG_PROMISCUOUS, 500);
				break;
			}
		}
	}
	public void sendPkt(MacAddr distMac,MacAddr srcMac,byte[] content){

	}

}
