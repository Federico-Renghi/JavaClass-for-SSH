package com.example.ssh;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.util.io.resource.PathResource;
import org.apache.sshd.common.util.security.SecurityUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Collections;

public class SSHClient {

    private static final Logger log = LoggerFactory.getLogger(SSHClient.class);

    private static final long TIMEOUT = 10_000;
    private static final int MAX_RETRIES = 3;
    private static final long RETRY_DELAY = 2000;

    private SshClient client;
    private ClientSession session;


    // COSTRUTTORE PASSWORD
    public SSHClient(String host, int port, String username, String password) throws Exception {
        initClient();

        session = connectWithRetry(host, port, username);

        log.info("Authenticating with password for user {}", username);

        session.addPasswordIdentity(password);
        session.auth().verify(TIMEOUT);

        log.info("Authentication successful");
    }

    // COSTRUTTORE CHIAVE (senza passphrase)
    public SSHClient(String host, int port, String username, Path privateKeyPath) throws Exception {
        this(host, port, username, privateKeyPath, null);
    }

    // COSTRUTTORE CHIAVE (con passphrase)
    public SSHClient(String host, int port, String username, Path privateKeyPath, String passphrase) throws Exception {
        initClient();

        session = connectWithRetry(host, port, username);

        log.info("Authenticating with private key {} for user {}", privateKeyPath, username);

        FilePasswordProvider provider = (passphrase == null)
                ? FilePasswordProvider.EMPTY
                : FilePasswordProvider.of(passphrase);

        try (InputStream inputStream = Files.newInputStream(privateKeyPath)) {

            Iterable<KeyPair> keys = SecurityUtils.loadKeyPairIdentities(
                    session,
                    new PathResource(privateKeyPath),
                    inputStream,
                    provider
            );

            for (KeyPair key : keys) {
                log.debug("Adding key identity: {}", key.getPublic().getAlgorithm());
                session.addPublicKeyIdentity(key);
            }
        }

        session.auth().verify(TIMEOUT);

        log.info("Authentication successful");
    }

    // INIT CLIENT
    private void initClient() {
        client = SshClient.setUpDefaultClient();
        client.start();

        log.info("SSH client started");
    }

    // RETRY CONNECTION
    private ClientSession connectWithRetry(String host, int port, String username) throws Exception {
        Exception lastException = null;

        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            try {
                log.info("Connecting to {}:{} as {} (attempt {}/{})", host, port, username, attempt, MAX_RETRIES);

                ClientSession session = client.connect(username, host, port)
                        .verify(TIMEOUT)
                        .getSession();

                log.info("Connection established");
                return session;

            } catch (Exception e) {
                log.warn("Connection attempt {} failed: {}", attempt, e.getMessage());
                lastException = e;

                if (attempt < MAX_RETRIES) {
                    Thread.sleep(RETRY_DELAY);
                }
            }
        }

        throw new RuntimeException("Failed to connect after " + MAX_RETRIES + " attempts", lastException);
    }

    // ESECUZIONE COMANDO
    public String executeCommand(String command) throws Exception {

        log.info("Executing command: {}", command);

        try (ByteArrayOutputStream out = new ByteArrayOutputStream();
             ByteArrayOutputStream err = new ByteArrayOutputStream();
             ClientChannel channel = session.createExecChannel(command)) {

            channel.setOut(out);
            channel.setErr(err);

            channel.open().verify(TIMEOUT);

            channel.waitFor(Collections.singleton(ClientChannelEvent.CLOSED), TIMEOUT);

            Integer exitStatus = channel.getExitStatus();

            String stdout = out.toString(StandardCharsets.UTF_8);
            String stderr = err.toString(StandardCharsets.UTF_8);

            log.debug("Command stdout: {}", stdout);
            log.debug("Command stderr: {}", stderr);

            if (exitStatus != null && exitStatus != 0) {
                log.error("Command failed with exit code {}: {}", exitStatus, stderr);
                throw new RuntimeException(
                        "Command failed (" + exitStatus + "): " + stderr
                );
            }

            return stdout;
        }
    }

    // CHIUDE CONNESSIONE
    public void close() {
        log.info("Closing SSH connection");

        try {
            if (session != null && session.isOpen()) {
                session.close(true);
                log.info("Session closed");
            }
        } catch (Exception e) {
            log.error("Error closing session", e);
        }

        try {
            if (client != null && !client.isClosed()) {
                client.stop();
                log.info("Client stopped");
            }
        } catch (Exception e) {
            log.error("Error stopping client", e);
        }
    }
}