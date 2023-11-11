package com.matterjs.util;

import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;

import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Console {
    private static final Logger logger = LoggerFactory.getLogger(Console.class);

    private ScheduledExecutorService executorService;
    private Thread inputThread;
    private boolean running = false;
    private Terminal terminal;
    private LineReader lineReader;
    public interface InputListener {
        void onInput(String input);
    }

    public Console(ScheduledExecutorService executorService) {
        this.executorService = executorService;
    }

    public void startConsole(String prompt, InputListener listener) {
        if (running) {
            throw new RuntimeException("Console already running");
        }
        running = true;
        try {
            terminal = TerminalBuilder.terminal();
            lineReader = LineReaderBuilder.builder()
                    .terminal(terminal)
                    .build();

            inputThread = new Thread(() -> {
                while (running) {
                    final String line = lineReader.readLine(prompt);
                    Future<?> f = executorService.submit(() -> {
                        listener.onInput(line);
                    });
                    try {
                        f.get();
                    } catch (InterruptedException | ExecutionException e) {
                        logger.error("Error running input", e);
                    }
                }
            });
            inputThread.start();
        } catch (Exception e) {
            logger.error("Error reading input", e);
        }
    }

    public void stopConsole() {
        running = false;
    }

    public  void prompt(String prompt) {
        if (lineReader != null) {
            lineReader.printAbove(prompt);
        }
    }
    public void write(String out) {
        if (terminal != null) {
            terminal.writer().println(out);
        }
    }
}
