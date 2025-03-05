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
import java.util.HashMap;

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

        //Cargar hash
        HashMap<String,String> dic = buscadorMD5();

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
                    if(dic.containsKey(cad)) {
                        m.setMensaje(dic.get(cad));
                    }else{
                        m.setMensaje("no esta almacenado");
                    }
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

    public static HashMap<String,String> buscadorMD5() throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(new File("Rainbow_Table.txt")));
        String linea;
        HashMap<String,String> resultado = new HashMap<>();
        while((linea = br.readLine())!= null){
            String[] cad = linea.split(",");
            resultado.put(cad[0],cad[1]);
        }
        return resultado;
    }


    public static String conversor(byte[] ent){
        return String.format("%02x", new BigInteger(1, ent));
    }


}

