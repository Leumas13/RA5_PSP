package Servidor;

import data.Mensaje;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;

public class Main {
    public static void main(String[] args) throws Exception {

        KeyStore almacen = KeyStore.getInstance("PKCS12");

        FileInputStream fis = new FileInputStream("miAlmacen.p12");
        almacen.load(fis, "123456".toCharArray());

        KeyManagerFactory km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        km.init(almacen, "123456".toCharArray());

        SSLContext contexto = SSLContext.getInstance("TLS");
        contexto.init(km.getKeyManagers(), null, null);

        SSLServerSocketFactory ssf = contexto.getServerSocketFactory();
        SSLServerSocket sss = (SSLServerSocket) ssf.createServerSocket(12345);
        System.out.println("Servidor SSL iniciado en el puerto 12345");

        SSLSocket socket = (SSLSocket) sss.accept();
        System.out.println("Cliente conectado.");


        //Crear fichero de hash
        crearRainbowTable();

        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());


        //Se crea el primer mensaje con las claves de todos los cifrados y se da la bienvenida
        Mensaje bienvenida = new Mensaje(201, "Bienvenido a este servidor de pruebas de programación segura");
        oos.writeObject(bienvenida);
        oos.flush();


        int cod;
        String cad;
        Mensaje m = (Mensaje)ois.readObject();
        do {


            cod = m.getCodigoMensaje();
            cad = m.getMensaje();

            switch(cod){
                case 101->{
                    m.reiniciarCampos();
                    m.setMensaje(buscadorMD5(cad));
                    m.setCodigoMensaje(201);

                    oos.writeObject(m);
                    oos.flush();
                    m = (Mensaje)ois.readObject();
                }


                case 0->{
                    m.reiniciarCampos();
                    m.setCodigoMensaje(999);
                    m.setMensaje("Servidor desconectado");

                    oos.writeObject(m);
                    oos.flush();
                }
                default -> {
                    m.reiniciarCampos();
                    m.setCodigoMensaje(100);
                    m.setMensaje("No existe en el menu");

                    oos.writeObject(m);
                    oos.flush();
                    m = (Mensaje)ois.readObject();
                }
            }
        }while(cod != 0);

        // 8. Cerrar las conexiones
        socket.close();
        sss.close();
        System.out.println("Conexión cerrada.");
    }


    public static void crearRainbowTable() throws IOException, NoSuchAlgorithmException {
        File f = new File("10-million-password-list-top-1000.txt");
        File f1 = new File("Rainbow_Table.txt");
        BufferedReader br = new BufferedReader(new FileReader(f));
        BufferedWriter bw = new BufferedWriter(new FileWriter(f1,false));

        String linea;
        while((linea = br.readLine())!=null){
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(linea.trim().getBytes(StandardCharsets.UTF_8));
            String hash = conversor(md.digest());
            bw.write(hash+","+linea);
            bw.newLine();
        }
        bw.close();
        br.close();
    }

    public static String buscadorMD5(String hash) throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(new File("Rainbow_Table.txt")));
        String linea;
        String resultado = "no existe";
        boolean flag = true;
        while((linea = br.readLine())!= null && flag){
            String[] cad = linea.split(",");
            if(hash.equals(cad[0])){
                resultado = cad[1];
                flag = false;
            }
        }
        return resultado;
    }


    public static String conversor(byte[] ent){
        return String.format("%02x", new BigInteger(1, ent));
    }


}

