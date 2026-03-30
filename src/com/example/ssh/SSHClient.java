package com.example.ssh;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.util.io.resource.PathResource;
import org.apache.sshd.common.util.security.SecurityUtils;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SSHClient {

    private static final Logger log = Logger.getLogger(SSHClient.class.getName());

    private static final long TIMEOUT = 10_000;
    private static final int MAX_RETRIES = 3;
    private static final long RETRY_DELAY = 2000;

    private final SshClient client;
    private final ClientSession session;

    //costruttore
    public SSHClient(
            String host,
            int port,
            String username,
            String password,
            Path privateKeyPath,
            String passphrase
    ) throws Exception {

        validateAuth(password, privateKeyPath);

        client = SshClient.setUpDefaultClient();
        client.start();

        log.info("SSH client started");

        session = connectWithRetry(host, port, username);

        if (password != null) {
            authenticateWithPassword(password, username);
        } else {
            authenticateWithKey(privateKeyPath, passphrase, username);
        }

        log.info("Authentication successful");
    }

    // validazione
    private void validateAuth(String password, Path key) {
        if (password != null && key != null) {
            throw new IllegalArgumentException(
                    "Specify either password or private key, not both"
            );
        }

        if (password == null && key == null) {
            throw new IllegalArgumentException(
                    "No authentication method provided"
            );
        }
    }

    // retry connessione
    private ClientSession connectWithRetry(String host, int port, String username) throws Exception {
        Exception lastException = null;

        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            try {
                log.info("Connecting to " + host + ":" + port + " as " + username +
                        " (attempt " + attempt + "/" + MAX_RETRIES + ")");

                ClientSession session = client.connect(username, host, port)
                        .verify(TIMEOUT)
                        .getSession();

                log.info("Connection established");
                return session;

            } catch (Exception e) {
                log.log(Level.WARNING, "Connection attempt " + attempt + " failed", e);
                lastException = e;

                if (attempt < MAX_RETRIES) {
                    Thread.sleep(RETRY_DELAY);
                }
            }
        }

        throw new RuntimeException("Failed to connect after retries", lastException);
    }

    // metodi di autenticazione
    private void authenticateWithPassword(String password, String username) throws Exception {
        log.info("Authenticating with password for user " + username);

        session.addPasswordIdentity(password);
        session.auth().verify(TIMEOUT);
    }

    private void authenticateWithKey(Path keyPath, String passphrase, String username) throws Exception {
        log.info("Authenticating with private key " + keyPath + " for user " + username);

        FilePasswordProvider provider = (passphrase == null)
                ? FilePasswordProvider.EMPTY
                : FilePasswordProvider.of(passphrase);

        try (InputStream inputStream = Files.newInputStream(keyPath)) {

            Iterable<KeyPair> keys = SecurityUtils.loadKeyPairIdentities(
                    session,
                    new PathResource(keyPath),
                    inputStream,
                    provider
            );

            for (KeyPair key : keys) {
                session.addPublicKeyIdentity(key);
            }
        }

        session.auth().verify(TIMEOUT);
    }

    // metodo per eseguire i comandi
    public String executeCommand(String command) throws Exception {

        log.info("Executing command: " + command);

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

            if (exitStatus != null && exitStatus != 0) {
                log.severe("Command failed (" + exitStatus + "): " + stderr);
                throw new RuntimeException("Command failed (" + exitStatus + "): " + stderr);
            }

            return stdout;
        }
    }

    // chiudi connessione
    public void close() {
        log.info("Closing SSH connection");

        try {
            if (session != null && session.isOpen()) {
                session.close(true);
            }
        } catch (Exception e) {
            log.log(Level.SEVERE, "Error closing session", e);
        }

        try {
            if (client != null && !client.isClosed()) {
                client.stop();
            }
        } catch (Exception e) {
            log.log(Level.SEVERE, "Error stopping client", e);
        }
    }
}