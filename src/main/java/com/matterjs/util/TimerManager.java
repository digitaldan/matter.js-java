package com.matterjs.util;

import java.util.*;
import java.util.concurrent.*;

import org.graalvm.polyglot.Context;

public class TimerManager {
    
    private final ScheduledExecutorService executor;
    private Timer timer = new Timer(true); // Daemon timer to allow application to exit
    private final Map<Integer, TimerTask> tasks = new ConcurrentHashMap<>();
    private int currentId = 0;
    
    public TimerManager(ScheduledExecutorService executor) {
        this.executor = executor;
    }

    public int setTimeout(JSFunction task, long delay) {
        TimerTask timerTask = new TimerTask() {
            public void run() {
                CompletableFuture.runAsync(task::call, executor);  // Shift execution to the provided executor
            }
        };
        executor.schedule(timerTask, delay, TimeUnit.MILLISECONDS);
        timer.schedule(timerTask, delay);
        tasks.put(currentId, timerTask);
        return currentId++;
    }

    public void clearTimeout(int taskId) {
        TimerTask task = tasks.remove(taskId);
        if (task != null) {
            task.cancel();

            if (tasks.isEmpty()) {
                timer.cancel();
                timer = new Timer(true); // Recreate the daemon timer
            }
        }
    }

    public int setInterval(JSFunction task, long interval) {
        TimerTask timerTask = new TimerTask() {
            public void run() {
                //CompletableFuture.runAsync(task::call, executor);  // Shift execution to the provided executor
                Context context = Context.getCurrent();
                synchronized(executor) {
                    context.enter();
                    task.call();
                    context.leave();
                }
            }
        };
        timer.scheduleAtFixedRate(timerTask, interval, interval);
        tasks.put(currentId, timerTask);
        return currentId++;
    }

    public void clearInterval(int taskId) {
        TimerTask task = tasks.remove(taskId);
        if (task != null) {
            task.cancel();
            if (tasks.isEmpty()) {
                timer.cancel();
                timer = new Timer(true); // Recreate the daemon timer
            }
        }
    }

    @FunctionalInterface
    public interface JSFunction {
        void call();
    }
}
