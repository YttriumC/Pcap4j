package cf.vbnm.pcap4j;

public final class Constant {
	/**
	 * 状态指示:
	 * 初始:
	 * 初始化    0
	 * 查找设备:
	 * 失败      1
	 * 成功      2
	 * 打开设备:
	 * 失败      3
	 * 成功      4
	 * 准备就绪:
	 * 5
	 * 关闭设备:
	 * 6
	 */
	public static final int WINPCAP_INIT = 0;
	public static final int WINPCAP_FIND_DEV_FAILURE = 1;
	public static final int WINPCAP_FIND_DEV_SUCCESS = 2;
	public static final int WINPCAP_OPEN_FAILURE = 3;
	public static final int WINPCAP_DEV_READY = 4;
	public static final int WINPCAP_OPEN_LOOP_CAPPING = 5;
	public static final int WINPCAP_CLOSED = 6;
	/**
	 * Flags defined in the openDevice() function
	 */
	public static final int PCAP_OPENFLAG_PROMISCUOUS = 1;
	//Defines if the adapter has to go in promiscuous mode.
	public static final int PCAP_OPENFLAG_DATATX_UDP = 2;
	//Defines if the data trasfer (in case of a remote capture) has to be done with UDP protocol.
	public static final int PCAP_OPENFLAG_NOCAPTURE_RPCAP = 4;
	//Defines if the remote probe will capture its own generated traffic.
	public static final int PCAP_OPENFLAG_NOCAPTURE_LOCAL = 8;
	//Defines if the local adapter will capture its own generated traffic.
	public static final int PCAP_OPENFLAG_MAX_RESPONSIVENESS = 16;
	//This flag configures the adapter for maximum responsiveness.
}
