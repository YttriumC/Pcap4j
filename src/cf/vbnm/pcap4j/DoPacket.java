package cf.vbnm.pcap4j;

public interface DoPacket {
	void captureLoopCallback(byte[] cap_pkt, int len, int tv_Sec, int tv_uSec);
}
