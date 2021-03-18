package cf.vbnm.pcap4j;

public interface PktProcessor {
	/**
	 * 回调方法, 捕获到一个数据包后如何操作
	 *
	 * @param cap_pkt 捕获到的数据帧
	 * @param len     封装的数据显示的长度
	 * @param tv_Sec  捕获到的时间的秒数
	 * @param tv_uSec 捕获到的时间的毫秒数
	 */
	void loopHandler(byte[] cap_pkt, int len, int tv_Sec, int tv_uSec);
}
