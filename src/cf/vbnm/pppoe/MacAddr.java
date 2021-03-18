package cf.vbnm.pppoe;

import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Arrays;

public class MacAddr {
	/**
	 * 广播地址
	 */
	public static final MacAddr broadCastMacAddr = new MacAddr(new byte[]{-1, -1, -1, -1, -1, -1});

	/**
	 * Mac地址
	 * */
	private byte[] macAddr;

	/**
	 * 根据已有mac地址构造mac对象
	 */
	public MacAddr(byte[] macAddr) {
		if (macAddr.length != 6)
			throw new IllegalArgumentException("Wrong Mac Address");
		this.macAddr = macAddr;
	}

	/**
	 * 获取本机Mac地址
	 */
	public MacAddr() throws IOException {
		InetAddress ia;
		byte[] mac = null;
		try {
			//获取本地IP对象
			ia = InetAddress.getLocalHost();
			//获得网络接口对象（即网卡），并得到mac地址，mac地址存在于一个byte数组中。
			mac = NetworkInterface.getByInetAddress(ia).getHardwareAddress();
		} catch (Exception e) {
			e.printStackTrace();
		}
		if (mac == null)
			throw new IOException("Can't get local machine MAC address");
		macAddr = mac;
	}

	/**
	 * 获取Mac地址
	 */
	public byte[] getMacAddr() {
		return macAddr;
	}

	/**
	 * 打印Mac地址
	 */
	@Override
	public String toString() {
		return "macAddr=" + Arrays.toString(macAddr).toUpperCase() + "\n";
	}
}
