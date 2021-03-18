package cf.vbnm.pcap4j;

import cf.vbnm.pcap4j.exceptions.*;

import java.io.File;

public class AbstractWinPcap {

	private int state;
	String[] devicesDescription;

	static {
		//TODO

		System.load(new File("lib\\pcap4j.dll").getAbsolutePath());
	}

	public AbstractWinPcap() {
		state = PcapConstant.WINPCAP_INIT;
	}

	/**
	 * 查找设备
	 *
	 * @throws FindDevicesException 设备查找问题
	 */
	public void findDevices() throws FindDevicesException {
		if (findDevices0() == 0) {
			state = PcapConstant.WINPCAP_FIND_DEV_FAILURE;
			throw new FindDevicesException("查找设备失败或者无网络设备.,也许你需要管理员权限");
		} else
			state = PcapConstant.WINPCAP_FIND_DEV_SUCCESS;
	}

	private native int findDevices0();

	/**
	 * 获取设备名称
	 *
	 * @return 返回设备的名称, 如果还没有查找设备, 返回null
	 */
	public String[] getDevicesList() {
		if (state < 2 || state == PcapConstant.WINPCAP_CLOSED) {
			return null;
		} else {
			if (devicesDescription == null)
				devicesDescription = obtainDevicesList();
			return devicesDescription;
		}
	}

	private native String[] obtainDevicesList();

	/**
	 * 选择设备
	 *
	 * @param index     设备序号
	 * @param maxCapLen 最大捕获长度
	 * @param flags     工作模式
	 * @param timeout   超时时间, 毫秒
	 */
	public void openDevice(int index, int maxCapLen, int flags, int timeout)
			throws ArgumentsException, FindDevicesException, PcapClosedException, OpenDeviceException {
		if (state < 2)
			throw new FindDevicesException("Devices are not find yet.");
		if (state == PcapConstant.WINPCAP_CLOSED)
			throw new PcapClosedException("设备已关闭");
		if (state >= PcapConstant.WINPCAP_DEV_READY)
			throw new OpenDeviceException("Devices has already opened.");
		if (index < 0 || index > devicesDescription.length - 1)
			throw new ArgumentsException("设备序号错误.");
		/*过短的数据包捕获就没用,这里应该是小于ip数据包的长度,忘了是多少*/
		if (maxCapLen < 20 || maxCapLen > 65536)
			maxCapLen = 65536;
		try {
			openDevice0(index, maxCapLen, flags, timeout);
			state = PcapConstant.WINPCAP_DEV_READY;
		} catch (OpenDeviceException e) {
			state = PcapConstant.WINPCAP_OPEN_FAILURE;
			e.printStackTrace();
		}
	}

	private native void openDevice0(int index, int maxCapLen
			, int flags, int timeout) throws OpenDeviceException;


	/**
	 * 开始捕获并调用回调方法处理数据
	 *
	 * @param cnt 抓包的个数, 0为一直抓取
	 * @param processor 处理数据包的接口
	 */
	public void loopCapture(int cnt, PktProcessor processor) throws OpenDeviceException, PcapClosedException {
		if (processor == null)
			throw new NullPointerException("packet processor is null");
		if (state < PcapConstant.WINPCAP_DEV_READY)
			throw new OpenDeviceException("设备还未打开");
		if (state == PcapConstant.WINPCAP_CLOSED)
			throw new PcapClosedException("设备已关闭");
		new Thread(() -> {
			loopCapture0(cnt, processor);
		}).start();
		state = PcapConstant.WINPCAP_OPEN_LOOP_CAPPING;
	}

	private native void loopCapture0(int cnt, PktProcessor processor);

	/**
	 * 停止捕获
	 */
	public void breakLoop() {
		if (state != PcapConstant.WINPCAP_OPEN_LOOP_CAPPING)
			return;
		breakLoop0();
		state = PcapConstant.WINPCAP_DEV_READY;
	}

	native void breakLoop0();

	/**
	 * 捕获下一个数据包
	 *
	 * @return 数据包的数据
	 */
	public byte[] capNext() {
		if (state != PcapConstant.WINPCAP_DEV_READY)
			return null;
		return capNext0();
	}

	private native byte[] capNext0();

	/**
	 * 发送一个数据包
	 *
	 * @param pkt 数据
	 * @throws SendPacketException Error sending the packet
	 */
	public void sendPacket(byte[] pkt) throws SendPacketException,
			OpenDeviceException, PcapClosedException {
		if (state < PcapConstant.WINPCAP_DEV_READY)
			throw new OpenDeviceException("Device not open yet");
		if (state == PcapConstant.WINPCAP_CLOSED)
			throw new PcapClosedException("设备已关闭");
		if (pkt == null || pkt.length == 0)
			return;
		sendPacket0(pkt, pkt.length);
	}

	/**
	 * 发送一个数据包
	 *
	 * @param pkt     数据
	 * @param sendLen 发送长度
	 * @throws SendPacketException Error sending the packet
	 */
	public boolean sendPacket(byte[] pkt, int sendLen) throws SendPacketException,
			OpenDeviceException, PcapClosedException {
		if (state < PcapConstant.WINPCAP_DEV_READY)
			throw new OpenDeviceException("Device not open yet");
		if (state == PcapConstant.WINPCAP_CLOSED)
			throw new PcapClosedException("设备已关闭");
		if (pkt == null || pkt.length == 0)
			return false;
		return sendPacket0(pkt, sendLen);
	}

	private native boolean sendPacket0(byte[] pkt, int sendLen) throws SendPacketException;

	/**
	 * 关闭这个捕获
	 */
	public void close() {
		if (state < PcapConstant.WINPCAP_DEV_READY)
			return;
		if (state == PcapConstant.WINPCAP_DEV_READY)
			close0();
		if (state == PcapConstant.WINPCAP_OPEN_LOOP_CAPPING) {
			breakLoop();
			close0();
		}
		state = PcapConstant.WINPCAP_CLOSED;
	}

	private native void close0();

	@Override
	protected void finalize() throws Throwable {
		close();
	}
}
