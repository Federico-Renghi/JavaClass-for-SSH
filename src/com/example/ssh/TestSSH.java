package com.example.ssh;

public class TestSSH {
    public static void main(String[] args) {
        try {
            SSHClient client = new SSHClient(
                    "localhost",
                    2222,
                    //9999,  porta sbagliata per test
                    "test",
                    "test",
                    null,
                    null
            );

            System.out.println("whoami:");
            System.out.println(client.executeCommand("whoami"));
/*
            System.out.println("pwd:");
            System.out.println(client.executeCommand("pwd"));

            System.out.println("ls:");
            System.out.println(client.executeCommand("ls"));
            */

            //System.out.println(client.executeCommand("comando inesistente"));

            client.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}