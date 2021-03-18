package cf.vbnm.pppoe;

import cf.vbnm.protocol.MACProtocolEnum;
import cf.vbnm.protocol.Protocols;

import java.util.Arrays;

public class Packet {
	private byte[] packet;
	private MacAddr localMac;
	private MacAddr remoteMac;
	private final int mtu;
	private int payloadLength;

	public Packet(MacAddr local, MacAddr remote, int mtu) {
		packet = new byte[mtu];
		localMac = local;
		remoteMac = remote;
		this.mtu = mtu;
		payloadLength = 0;
	}

	public void setContent(byte[] content) {
		System.arraycopy(content, 0, packet, 14, Math.min(content.length, (mtu - 14)));
	}

	/**
	 * @param isOut 本机发出, isOut==true 反之亦然
	 */
	public byte[] getPacket(boolean isOut) {
		if (isOut) {
			System.arraycopy(remoteMac.getMacAddr(), 0, packet, 0, 6);
			System.arraycopy(localMac.getMacAddr(), 0, packet, 6, 6);
		} else {
			System.arraycopy(localMac.getMacAddr(), 0, packet, 0, 6);
			System.arraycopy(remoteMac.getMacAddr(), 0, packet, 6, 6);
		}
		return packet;
	}

	public byte[] getPacket(boolean isOut, MACProtocolEnum protocol) {
		short MacProtocol = Protocols.getMacProtocol(protocol);
		getPacket(isOut);
		packet[12] = (byte) (MacProtocol >> 8);
		packet[13] = (byte) MacProtocol;
		return packet;
	}

	public void setPayload(byte[] packet) {
		this.packet = packet;
	}

	public void addPayload(byte[] packet, int length) {
		System.arraycopy(packet, 0, this.packet,
				payloadLength + 14, Math.min(length, mtu - 14));
	}

	public void addPayload(byte data) {
		if (payloadLength + 14 < mtu) {
			this.packet[payloadLength + 14] = data;
			payloadLength++;
		}
	}

	public void addPayload(short data) {
		if (payloadLength + 15 < mtu) {
			packet[payloadLength + 14] = (byte) (data >> 8);
			packet[payloadLength + 15] = (byte) data;
		}
	}

	public MacAddr getLocalMac() {
		return localMac;
	}

	public void setLocalMac(MacAddr localMac) {
		this.localMac = localMac;
	}

	public MacAddr getRemoteMac() {
		return remoteMac;
	}

	public void setRemoteMac(MacAddr remoteMac) {
		this.remoteMac = remoteMac;
	}
}
