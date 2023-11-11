package com.matterjs.util;

import java.util.concurrent.*;
import java.util.function.Consumer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LoggingScheduledExecutorService extends ScheduledThreadPoolExecutor {
    private static final Logger logger = LoggerFactory.getLogger(LoggingScheduledExecutorService.class);

    public LoggingScheduledExecutorService() {
        // 1 thread for all JS execution, critical for GraalVM Javascript interop
        super(1);
    }

    public ScheduledFuture<?> scheduleAtFixedRateJS(Consumer<String> command, long initialDelay, long period) {
        logger.trace("scheduleAtFixedRate: consumer: " + command + ", initialDelay: " + initialDelay + ", period: "
                + period);
        return super.scheduleAtFixedRate(wrapWithLogging(new Runnable() {
            @Override
            public void run() {
                logger.trace("scheduleAtFixedRate RUN: consumer: " + command + ", initialDelay: " + initialDelay
                        + ", period: " + period);
                command.accept("foo");
            }
        }), initialDelay, period, TimeUnit.MILLISECONDS);
    }

    public ScheduledFuture<?> scheduleJS(Consumer<Void> command, long delay) {
        logger.trace("schedule: consumer: " + command + ", delay: " + delay);
        return super.schedule(wrapWithLogging(new Runnable() {
            @Override
            public void run() {
                logger.trace("schedule RUN: consumer: " + command + ", delay: " + delay);
                command.accept(null);
            }
        }), delay, TimeUnit.MILLISECONDS);
    }

    @Override
    public ScheduledFuture<?> schedule(Runnable command, long delay, TimeUnit unit) {
        String commandNameString = command.toString();
        boolean logit = !commandNameString.contains("com.matterjs.net.AsyncDatagramReceiver");
        if (logit) {
            logger.trace("schedule: command: " + command + ", delay: " + delay + ", unit: " + unit);
        }
        return super.schedule(wrapWithLogging(command), delay, unit);
    }

    @Override
    public <V> ScheduledFuture<V> schedule(Callable<V> callable, long delay, TimeUnit unit) {
        logger.trace("schedule: callable: " + callable + ", delay: " + delay + ", unit: " + unit);
        return super.schedule(wrapWithLogging(callable), delay, unit);
    }

    @Override
    public ScheduledFuture<?> scheduleAtFixedRate(Runnable command, long initialDelay, long period, TimeUnit unit) {
        logger.trace("scheduleAtFixedRate: command: " + command + ", initialDelay: " + initialDelay + ", period: "
                + period + ", unit: " + unit);
        return super.scheduleAtFixedRate(wrapWithLogging(command), initialDelay, period, unit);
    }

    @Override
    public ScheduledFuture<?> scheduleWithFixedDelay(Runnable command, long initialDelay, long delay, TimeUnit unit) {
        logger.trace("scheduleWithFixedDelay: command: " + command + ", initialDelay: " + initialDelay + ", delay: "
                + delay + ", unit: " + unit);
        return super.scheduleWithFixedDelay(wrapWithLogging(command), initialDelay, delay, unit);
    }

    private Runnable wrapWithLogging(Runnable command) {
        return () -> {
            logger.trace("Before executing the Runnable... {}", command);
            try {
                command.run();
            } finally {
                logger.trace("After executing the Runnable...");
            }
        };
    }

    private <V> Callable<V> wrapWithLogging(Callable<V> callable) {
        return () -> {
            logger.trace("Before executing the Callable...");
            try {
                return callable.call();
            } finally {
                logger.trace("After executing the Callable...");
            }
        };
    }
}