package cf.vbnm.protocol;

public class Protocols {
	public static short getMacProtocol(MACProtocolEnum protocolType) {

		return switch (protocolType) {
			case PPPoED -> (short) 0x8863;

			case PPPSession -> (short) 0x8864;

			case IPv4 -> (short) 0x0800;

			case IPv6 -> (short) 0x86dd;

		};
	}

	public static short getPPPProtocol(PPPProtocols protocolType) {
		return switch (protocolType) {
			case IPv4 -> (short) 0x0021;
			case IPv6 -> (short) 0x0000;
		};
	}
}
