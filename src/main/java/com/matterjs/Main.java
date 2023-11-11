package com.matterjs;

import java.io.File;
import java.nio.file.Paths;
import java.util.concurrent.ScheduledExecutorService;

import org.graalvm.polyglot.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.matterjs.net.AsyncDatagramReceiver;
import com.matterjs.util.Console;
import com.matterjs.util.LoggingScheduledExecutorService;
import com.matterjs.util.TimerManager;

public class Main implements ControllerEventListener {
    private static final Logger logger = LoggerFactory.getLogger(Main.class);
    // executorService provides a single thread for all JS execution, critical for
    // GraalVM Javascript interop
    private ScheduledExecutorService executorService = new LoggingScheduledExecutorService();
    private Context context;
    private Globals globals;

    public Main(String[] commandArguments) {
        String wd = Paths.get(".").toAbsolutePath().normalize().toString();
        try {
            context = Context.newBuilder().allowAllAccess(true)
                    .option("js.commonjs-require", "true") // Enable CommonJS module support
                    .option("js.commonjs-require-cwd", wd + "/node_modules")
                    .build();

            // Javascript will see a 'Globals' object with the following properties:
            globals = new Globals(this, commandArguments, executorService, new TimerManager(executorService),
                    new AsyncDatagramReceiver(executorService), new Console(executorService));
            context.getBindings("js").putMember("Globals", globals);

            //load our node polyfill
            Source source = Source.newBuilder("js", new File("./src/main/js/globals.js")).build();
            context.eval(source);

            //load the webpack bundle
            source = Source.newBuilder("js", new File("./dist/bundle.js")).build();
            context.eval(source);

            //execute the startApp() function on our main execution thread, where all calls to JS must be made from
            executorService.submit(() -> {
                try {
                    Value v = context.eval("js", "startApp()");
                    logger.debug("Source Loaded!", v.asString());
                } catch (Exception e) {
                    logger.error("Error running main JS", e);
                }
            });

        } catch (Exception e) {
            logger.error("Error running GraalVM", e);
        }
    }

    public void fatalError(String message) {
        logger.error("fatalError: " + message);
        globals.executorService.shutdown();
        globals.asyncDatagramReceiver.shutdown();
        System.exit(1);
    }

    public class Globals {
        public ControllerEventListener controllerEventListener;
        public String[] commandArguments;
        public ScheduledExecutorService executorService;
        public TimerManager timerManager;
        public AsyncDatagramReceiver asyncDatagramReceiver;
        public Console console;

        public Globals(ControllerEventListener controllerEventListener, String[] commandArguments,
                ScheduledExecutorService executorService, TimerManager timerManager,
                AsyncDatagramReceiver asyncDatagramReceiver,
                Console console) {
            this.controllerEventListener = controllerEventListener;
            this.commandArguments = commandArguments;
            this.executorService = executorService;
            this.timerManager = timerManager;
            this.asyncDatagramReceiver = asyncDatagramReceiver;
            this.console = console;
        }
    }

    public static void main(String[] args) {
        Main main = new Main(args);
    }

}
