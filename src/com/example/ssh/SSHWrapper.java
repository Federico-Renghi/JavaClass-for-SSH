package com.example.ssh;

public class SSHWrapper
{
    public static Object runTest() {
        SSHClient client = null;
        try {
            client = new SSHClient(
                    "localhost",
                    2222,
                    "test",
                    "test"
            );

            String result = client.executeCommand("echo 'hello'");
            return result;

        } catch (Exception e) {
            throw new RuntimeException("Errore durante test SSH", e);

        } finally {
            if (client != null) {
                client.close();
            }
        }
    }
}
