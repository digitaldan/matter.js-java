import { UdpChannel, UdpChannelOptions } from "@project-chip/matter.js/net";
import { ByteArray } from "@project-chip/matter.js/util";
import { Logger } from "@project-chip/matter.js/log";

declare const Java: any;
declare const Globals: any;

const DatagramChannel = Java.type("java.nio.channels.DatagramChannel");
const ByteBuffer = Java.type("java.nio.ByteBuffer");
const InetSocketAddress = Java.type("java.net.InetSocketAddress");
const InetAddress = Java.type("java.net.InetAddress");
const NetworkInterface = Java.type("java.net.NetworkInterface");
const StandardSocketOptions = Java.type("java.net.StandardSocketOptions");
const logger = Logger.get("UdpChannelNode");

export class UdpChannelNode implements UdpChannel {
    private channel: any;
    private membershipKey: any | null = null;
    private options: UdpChannelOptions

    constructor(options: UdpChannelOptions) {

        const supportsIPv4 = function(networkInterface:any){
            const addresses = networkInterface.getInetAddresses();
            while (addresses.hasMoreElements()) {
                const address = addresses.nextElement();
                if (address instanceof InetAddress && !address.isLoopbackAddress() && !address.isLinkLocalAddress() && !address.isMulticastAddress()) {
                    return address.getAddress().length === 4;
                }
            }
            return false;
        }
        const supportsIPv6 = function(networkInterface:any){
            const addresses = networkInterface.getInetAddresses();
            while (addresses.hasMoreElements()) {
                const address = addresses.nextElement();
                if (address instanceof InetAddress && !address.isLoopbackAddress() && !address.isLinkLocalAddress() && !address.isMulticastAddress()) {
                    return address.getAddress().length === 16;
                }
            }
            return false;
        }

        this.options = options;
        logger.debug(`UdpChannelNode.constructor ${JSON.stringify(options)}`);
        this.channel = DatagramChannel.open();
        this.channel.setOption(StandardSocketOptions.SO_REUSEADDR, true);
        if (options.type === "udp6") {
            this.channel = this.channel.bind(new InetSocketAddress(options.listeningAddress || "::0", options.listeningPort || 0));
        } else {
            this.channel = this.channel.bind(new InetSocketAddress(options.listeningAddress || "0.0.0.0", options.listeningPort || 0));
        }

        if (options.membershipAddresses && options.membershipAddresses.length > 0) {
            logger.debug("UdpChannelNode.constructor checking multicast");
            const networkInterfaces = [];
            if (options.netInterface) {
                networkInterfaces.push(NetworkInterface.getByName(options.netInterface));
            } else {
                const interfaces = NetworkInterface.getNetworkInterfaces();
                while (interfaces.hasMoreElements()) {
                    networkInterfaces.push(interfaces.nextElement());
                }
            }
            for (const networkInterface of networkInterfaces) {
                if (options.type === "udp6" && !supportsIPv6(networkInterface)) {
                    continue;
                }
                if (options.type === "udp4" && !supportsIPv4(networkInterface)) {
                    continue;
                }
                if (networkInterface.isUp()) {
                    logger.debug(`UdpChannelNode.constructor enabling multicast on interface ${networkInterface.getName()}`);
                    this.channel.configureBlocking(true);
                    for (const membershipAddress of options.membershipAddresses) {
                        logger.debug(`UdpChannelNode.constructor joining ${membershipAddress}`);
                        this.membershipKey = this.channel.join(InetAddress.getByName(membershipAddress), networkInterface);
                        logger.debug(`UdpChannelNode.constructor joining ${membershipAddress} done ${this.membershipKey}`);

                    }
                }
            }
        }
    }

    onData(listener: (netInterface: string, peerAddress: string, peerPort: number, data: ByteArray) => void) {
        logger.debug(`UdpChannelNode.onData ${JSON.stringify(listener)}`);

        if (!listener) {
            logger.debug(`UdpChannelNode.onData listener is null`);
        }

        Globals.asyncDatagramReceiver.startChannel(this.channel, (udpChannelListener: any) => {
            const returnData = new Uint8Array(udpChannelListener.data)
            //logger.debug(`UdpChannelNode.onData len ${returnData.length} « ${returnData}`);
            listener(this.options.netInterface ?? "", udpChannelListener.addr.getAddress().getHostAddress(), udpChannelListener.addr.getPort(), returnData);
        });

        logger.debug(`AsyncDatagramReceiver registered`);

        return {
            close: async () => {
                if (this.membershipKey) {
                    this.membershipKey.drop();
                }
                this.channel.close();
            }
        };
    }

    async send(host: string, port: number, data: ByteArray): Promise<void> {
        const buffer = ByteBuffer.wrap(new Int8Array(data));
        const num = this.channel.send(buffer, new InetSocketAddress(host, port));
        //logger.debug(`UdpChannelNode.send ${host} ${port} ${data} bytes sent ${num}`);
    }

    close(): void {
        if (this.membershipKey) {
            this.membershipKey.drop();
        }
        this.channel.close();
    }
}