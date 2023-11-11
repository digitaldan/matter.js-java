import { NetworkError, Network, UdpChannelOptions, UdpChannel} from  "@project-chip/matter.js/net";
import { UdpChannelNode } from "./UdpChannelNode";

declare const Java:any;
const NetworkInterface = Java.type("java.net.NetworkInterface");

export class NetworkNode extends Network {
    getNetInterfaces(): string[] {
        const interfaces = NetworkInterface.getNetworkInterfaces();
        const result = [];
        while (interfaces.hasMoreElements()) {
            result.push(interfaces.nextElement().getName());
        }
        return result;
    }

    getIpMac(netInterface: string): { mac: string; ips: string[] } | undefined {
        const interfaceObj = NetworkInterface.getByName(netInterface);
        if (interfaceObj) {
            const mac = new Uint8Array(interfaceObj.getHardwareAddress()).join(":");
            const addresses = interfaceObj.getInetAddresses();
            const ips = [];
            while (addresses.hasMoreElements()) {
                ips.push(addresses.nextElement().getHostAddress());
            }
            return { mac, ips };
        }
        return undefined;
    }

    async createUdpChannel(options: UdpChannelOptions): Promise<UdpChannel> {
        return new UdpChannelNode(options);
    }
}
