package Cliente;


import data.Mensaje;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.*;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Scanner;

public class Main {
    static Scanner sc = new Scanner(System.in);
    public static void main(String[] args) throws Exception {

        Socket socket = new Socket("localhost", 12345);

        //Generar claves cliente
        KeyStore almacen = KeyStore.getInstance("PKCS12");

        FileInputStream fis = new FileInputStream("miAlmacenCliente.p12");
        almacen.load(fis, "123456".toCharArray());

        PublicKey clavePublicaCliente = almacen.getCertificate("cliente").getPublicKey();
        PrivateKey clavePrivadaCliente = (PrivateKey) almacen.getKey("cliente", "123456".toCharArray());

        int cod;
        String cad;
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());


        SecretKey claveSimetrica = null;
        PublicKey clavePublicaServer = null;
        SecretKey pass = null;


        Mensaje m = (Mensaje) ois.readObject();
        do {
            cod = m.getCodigoMensaje();
            cad = m.getMensaje();
            //Desencriptar respuestas de servidor
            switch (cod){
                case 500 ->{ //bienvenida e intercambio de claves
                    claveSimetrica = m.getClaveSimetrica();
                    clavePublicaServer = m.getClavePublicaServidor();
                    System.out.println(cad);

                    //enviar clave publica
                    m.reiniciarCampos();

                    m.setCodigoMensaje(101);
                    m.setClavePublicaCliente(clavePublicaCliente);

                    oos.writeObject(m);
                    oos.flush();
                    m = (Mensaje) ois.readObject();

                    System.out.println(m.getMensaje());

                }
                case 201 ->{ //recibe un string sin encriptar
                    System.out.println(cad);
                }
                case 202 ->{ //recibe un mensaje con clave simetrica
                    Cipher cifrador = Cipher.getInstance(claveSimetrica.getAlgorithm());
                    cifrador.init(Cipher.DECRYPT_MODE, claveSimetrica);
                    byte[] resultado = cifrador.doFinal(m.getCifrado());

                    System.out.println(new String(resultado, StandardCharsets.UTF_8));
                }
                case 203 ->{ //recibe un mensaje de clave asimétrica
                    Cipher cifrador = Cipher.getInstance(clavePrivadaCliente.getAlgorithm());
                    cifrador.init(Cipher.DECRYPT_MODE, clavePrivadaCliente);
                    byte[] resultado = cifrador.doFinal(m.getCifrado());

                    System.out.println(new String(resultado, StandardCharsets.UTF_8));
                }
                case 204 ->{ //recibe un mensaje con clave híbrida
                    Cipher cifrador = Cipher.getInstance(pass.getAlgorithm());
                    cifrador.init(Cipher.DECRYPT_MODE, pass);
                    byte[] resultado = cifrador.doFinal(m.getCifrado());

                    System.out.println(new String(resultado, StandardCharsets.UTF_8));
                }
                case 501 ->{ //Confirmar el intercambio de claves
                    System.out.println(cad);
                }
            }

            if(cod != 999) {
                System.out.println("""
                        Menu
                        1. Enviar un mensaje con cifrado simétrico
                        2. Enviar un mensaje con cifrado asimétrico
                        3. Enviar un mensaje con cifrado híbrido
                        4. Firmar un mensaje
                        
                        0. Salir""");
                cod = Integer.parseInt(sc.nextLine());
            }else{
                System.out.println(cad); //mensaje confirmacion de salida del servidor
            }
            switch (cod){
                case 1 ->{
                    System.out.println("Esta comunicacion está protegida por clave simétrica");
                    System.out.print("Escribe el mensaje que se envía con clave simétrica: ");

                    if (claveSimetrica != null) {
                        Cipher cifrador = Cipher.getInstance(claveSimetrica.getAlgorithm());
                        cifrador.init(Cipher.ENCRYPT_MODE, claveSimetrica);
                        String mensaje = sc.nextLine();
                        byte[] resultado = cifrador.doFinal(mensaje.getBytes());

                        m.reiniciarCampos();
                        m.setCodigoMensaje(102);
                        m.setCifrado(resultado);

                        oos.writeObject(m);
                        oos.flush();
                        m = (Mensaje) ois.readObject();
                    }else{
                        System.out.println("Conexion fallida, no existe clave simétrica");

                        m.reiniciarCampos();
                        m.setCodigoMensaje(0);
                        m.setMensaje("");

                        oos.writeObject(m);
                        oos.flush();
                        m = (Mensaje) ois.readObject();
                    }

                }
                case 2 ->{
                    System.out.println("Esta comunicacion está protegida por clave asimétrica");
                    System.out.print("Escribe el mensaje que se envía con clave asimétrica: ");

                    if (clavePublicaServer != null) {
                        Cipher cifrador = Cipher.getInstance(clavePublicaServer.getAlgorithm());
                        cifrador.init(Cipher.ENCRYPT_MODE, clavePublicaServer);
                        String mensaje = sc.nextLine();
                        byte[] resultado = cifrador.doFinal(mensaje.getBytes());

                        m.reiniciarCampos();
                        m.setCodigoMensaje(103);
                        m.setCifrado(resultado);

                        oos.writeObject(m);
                        oos.flush();
                        m = (Mensaje) ois.readObject();
                    }else{
                        System.out.println("Conexion fallida, no existe clave simétrica");

                        m.reiniciarCampos();
                        m.setCodigoMensaje(0);
                        m.setMensaje("");

                        oos.writeObject(m);
                        oos.flush();
                        m = (Mensaje) ois.readObject();
                    }
                }
                case 3 ->{
                    System.out.println("Esta comunicacion está protegida por cifrado híbrido");
                    System.out.print("Escribe el mensaje que se envía con clave asimétrica: ");
                    String mensaje = sc.nextLine();

                    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                    keyGen.init(256); // Tamaño de la clave
                    pass = keyGen.generateKey();

                    if (clavePublicaServer != null) {
                        //cifrar la clave AES con la publica del servidor
                        Cipher cifrador = Cipher.getInstance(clavePublicaServer.getAlgorithm());
                        cifrador.init(Cipher.ENCRYPT_MODE, clavePublicaServer);
                        byte[] claveCifrada = cifrador.doFinal(pass.getEncoded());

                        //cifrar mensaje con la clave AES
                        Cipher cifradorAES = Cipher.getInstance(pass.getAlgorithm());
                        cifradorAES.init(Cipher.ENCRYPT_MODE, pass);
                        byte[] resultadoAES = cifrador.doFinal(mensaje.getBytes());

                        //enviar mensaje y clave cifrada
                        m.reiniciarCampos();
                        m.setCodigoMensaje(105);
                        m.setCifrado(resultadoAES);
                        m.setClaveCifrada(claveCifrada);


                        oos.writeObject(m);
                        oos.flush();
                        m = (Mensaje) ois.readObject();
                    }else{
                        System.out.println("Conexion fallida, no existe clave simétrica");

                        m.reiniciarCampos();
                        m.setCodigoMensaje(0);
                        m.setMensaje("");

                        oos.writeObject(m);
                        oos.flush();
                        m = (Mensaje) ois.readObject();
                    }
                }
                case 4 ->{

                    System.out.println("Esta comunicacion esta protegida por una firma");
                    System.out.print("Escribe el mensaje para firmar: ");

                    Signature signature = Signature.getInstance("SHA256withRSA");
                    signature.initSign(clavePrivadaCliente);
                    String mensaje = sc.nextLine();
                    signature.update(mensaje.getBytes());

                    byte[] textoFirmado = signature.sign();

                    m.reiniciarCampos();
                    m.setCodigoMensaje(104);
                    m.setCifrado(textoFirmado);
                    m.setMensaje(mensaje);

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
        System.out.println("Conexión cerrada");
    }
}
