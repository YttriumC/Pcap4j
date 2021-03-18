package cf.vbnm.pppoe;

import cf.vbnm.pcap4j.AbstractWinPcap;
import cf.vbnm.pcap4j.PktProcessor;
import cf.vbnm.pcap4j.exceptions.OpenDeviceException;
import cf.vbnm.pcap4j.exceptions.PcapClosedException;
import cf.vbnm.pcap4j.exceptions.SendPacketException;
import cf.vbnm.protocol.MACProtocolEnum;
import org.junit.Test;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Properties;


public class PPP implements PktProcessor {

	private String userName;
	private String password;

	private static final byte version = 0x01;
	private static final byte type = 0x10;
	//session data
	private byte code;
	private short SessionID;
	private short payloadLength;
	private static final byte[] pppoeTags = {0x06, 0, 0, 0, 0, 0, 0, 0, 0x0C, 0, 0, 0};

//	public PPP(String userName, String password) {
//		this.userName = userName;
//		this.password = password;
//		code = 0x09;
//	}

	public void addPPPSession(Packet packet) {
		packet.addPayload((byte) (version | type));
		packet.addPayload(code);
		packet.addPayload(payloadLength);
	}

	public PPP() {

	}

	@Test
	public void test() {
		try {
			Runtime.getRuntime().exec("rasdial Dr.COM \"" + String.valueOf(new char[]{(char) 0x0d, (char) 0x0a}) + "2019407229\" 045012");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * 回调方法, 捕获到一个数据包后如何操作
	 *
	 * @param cap_pkt 捕获到的数据帧
	 * @param len     封装的数据显示的长度
	 * @param tv_Sec  捕获到的时间的秒数
	 * @param tv_uSec 捕获到的时间的毫秒数
	 */
	@Override
	public void loopHandler(byte[] cap_pkt, int len, int tv_Sec, int tv_uSec) {

	}

	public boolean startAuth(AbstractWinPcap device, Packet packet) {
		packet.addPayload(pppoeTags, pppoeTags.length);

		try {
			device.sendPacket(packet.getPacket(true, MACProtocolEnum.PPPoED));
		} catch (SendPacketException | OpenDeviceException | PcapClosedException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}
}
