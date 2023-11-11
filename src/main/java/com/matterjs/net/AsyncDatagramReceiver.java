package com.matterjs.net;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.function.Consumer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AsyncDatagramReceiver {
    private static final Logger logger = LoggerFactory.getLogger(AsyncDatagramReceiver.class);
    private final ScheduledExecutorService executorService;
    private final ExecutorService networkExecutorService = Executors.newCachedThreadPool();

    public AsyncDatagramReceiver(ScheduledExecutorService executorService) {
        this.executorService = executorService;
    }

   public void startChannel(DatagramChannel channel, Consumer<UdpChannelListener> callback) {
        networkExecutorService.submit(() -> {
            try {
                channel.configureBlocking(true);
                ByteBuffer buffer = ByteBuffer.allocate(2048);
                while (channel.isOpen()) {
                    buffer.clear();
                    //logger.debug("receiveAsync: channel: " + channel + ", buffer: " + buffer);
                    InetSocketAddress addr = (InetSocketAddress) channel.receive(buffer);
                    byte[] data = new byte[buffer.position()];
                    buffer.rewind();
                    buffer.get(data);
                    //logger.debug("receiveAsync: addr: " + addr);
                    executorService.submit(() -> {
                        callback.accept(new UdpChannelListener(data, addr));
                    });
                }
            } catch (Exception e) {
                logger.debug("receiveAsync failed", e);
            }
        });
    }

    public class UdpChannelListener {
        public byte[] data;
        public InetSocketAddress addr;

        public UdpChannelListener(byte[] data, InetSocketAddress addr) {
            this.data = data;
            this.addr = addr;
        }
    }

    // Clean up resources when you're done
    public void shutdown() {
        executorService.shutdown();
    }

}
