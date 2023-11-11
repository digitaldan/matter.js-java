package com.matterjs.storage;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Storage {
    private static final Logger logger = LoggerFactory.getLogger(Storage.class);

    public static void write(String path, String data) throws RuntimeException {
        try {
            Files.write(Paths.get(path), data.getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (IOException e) {
            logger.error("Write failed", e);
            throw new RuntimeException(e);
        }
    }

    public static String read(String path) throws RuntimeException {
        try {
            return new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);
        } catch (NoSuchFileException e) {
            return "";
        } catch (IOException e) {
            logger.error("Read failed", e);
            throw new RuntimeException(e);
        }
    }
}
