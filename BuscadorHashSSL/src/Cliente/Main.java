package Cliente;


import data.Mensaje;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.net.ssl.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

public class Main {
    static Scanner sc = new Scanner(System.in);
    public static void main(String[] args) throws Exception {

        //Generar claves cliente
        KeyStore almacen = KeyStore.getInstance("PKCS12");

        FileInputStream fis = new FileInputStream("miAlmacenCliente.p12");
        almacen.load(fis, "123456".toCharArray());


        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(almacen);
        SSLContext contexto = SSLContext.getInstance("TLS");
        contexto.init(null,tmf.getTrustManagers(),null);
        SSLSocket socket = (SSLSocket) contexto.getSocketFactory().createSocket("localhost",12345);


        PublicKey clavePublicaCliente = almacen.getCertificate("cliente").getPublicKey();
        PrivateKey clavePrivadaCliente = (PrivateKey) almacen.getKey("cliente", "123456".toCharArray());

        int cod;
        String cad;
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());


        SecretKey claveSimetrica = null;
        PublicKey clavePublicaServer = null;


        Mensaje m = (Mensaje) ois.readObject();

        do {
            cod = m.getCodigoMensaje();
            cad = m.getMensaje();

            System.out.println(cad);
            if(cod != 999) {
                System.out.println("""
                        Menu
                        1. Comprobar si existe un hash por fuerza bruta
                        
                        0. Salir""");
                cod = Integer.parseInt(sc.nextLine());
            }
            switch (cod){
                case 1 ->{
                    System.out.println("Esta comunicacion está protegida por SSL");
                    System.out.print("Escribe el hash que quieres comparar: ");

                    m.reiniciarCampos();
                    m.setCodigoMensaje(101);
                    m.setMensaje(sc.nextLine());

                    oos.writeObject(m);
                    oos.flush();
                    m = (Mensaje) ois.readObject();
                }

                case 0 ->{
                    m.reiniciarCampos();
                    m.setCodigoMensaje(0);

                    oos.writeObject(m);
                    oos.flush();
                    m = (Mensaje) ois.readObject();
                }
            }

        } while (cod != 999);

        // 4. Cerrar la conexión
        socket.close();
        System.out.println("Conexión cerrada.");
    }

}
