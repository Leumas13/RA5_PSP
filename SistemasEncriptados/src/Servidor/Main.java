package Servidor;

import data.Mensaje;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;

public class Main {
    public static void main(String[] args) throws Exception {

        KeyStore almacen = KeyStore.getInstance("PKCS12");

        FileInputStream fis = new FileInputStream("miAlmacen.p12");
        almacen.load(fis, "123456".toCharArray());

        ServerSocket servidor=new ServerSocket(12345);

        Socket socket = servidor.accept();
        System.out.println("Cliente conectado.");



        //Generar clave simetrica en AES
        SecretKey claveSimetrica = claveSimetrica();

        //Generar clave publica
        PublicKey clavePublica = almacen.getCertificate("servidor").getPublicKey();

        //Generar clave privada
        PrivateKey clavePrivada = (PrivateKey) almacen.getKey("servidor","123456".toCharArray());

        //Clave publica de cliente
        PublicKey clavePublicaCliente = null;

        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());


        //Se crea el primer mensaje con las claves de todos los cifrados y se da la bienvenida
        Mensaje bienvenida = new Mensaje(500, "Bienvenido a este servidor de pruebas de programación segura", claveSimetrica, clavePublica);
        oos.writeObject(bienvenida);
        oos.flush();


        int cod;
        String cad;
        Mensaje m = (Mensaje)ois.readObject();
        do {
            cod = m.getCodigoMensaje();
            cad = m.getMensaje();
            switch(cod){
                case 101->{ //Conexion, almacenamiento de clave publica del cliente
                    clavePublicaCliente = m.getClavePublicaCliente();
                    System.out.println("ya estoy aqui");
                    m.reiniciarCampos();
                    m.setMensaje("Claves compartidas con existo");

                    oos.writeObject(m);
                    oos.flush();
                    m = (Mensaje)ois.readObject();
                }
                case 102->{ //cifrado simetrico
                    Cipher cifrador = Cipher.getInstance(claveSimetrica.getAlgorithm());
                    cifrador.init(Cipher.DECRYPT_MODE, claveSimetrica);
                    byte[] resultado = cifrador.doFinal(m.getCifrado());

                    String mensajeDescifrado = new String(resultado, StandardCharsets.UTF_8);
                    String mensajeVuelta = "Tu mensaje lo leido y vuelto a encriptar con Simétrica, era: " + mensajeDescifrado;
                    cifrador.init(Cipher.ENCRYPT_MODE, claveSimetrica);
                    resultado = cifrador.doFinal(mensajeVuelta.getBytes());

                    m.reiniciarCampos();
                    m.setCodigoMensaje(202);
                    m.setCifrado(resultado);

                    oos.writeObject(m);
                    oos.flush();
                    m = (Mensaje)ois.readObject();
                }
                case 103->{ //cifrado asimetrico
                    Cipher cifrador = Cipher.getInstance(clavePrivada.getAlgorithm());
                    cifrador.init(Cipher.DECRYPT_MODE, clavePrivada);
                    byte[] resultado = cifrador.doFinal(m.getCifrado());

                    String mensajeDescifrado = new String(resultado, StandardCharsets.UTF_8);
                    String mensajeVuelta = "Tu mensaje lo leido y vuelto a encriptar con Asimétrica, era: " + mensajeDescifrado;
                    cifrador.init(Cipher.ENCRYPT_MODE, clavePublicaCliente);
                    resultado = cifrador.doFinal(mensajeVuelta.getBytes());

                    m.reiniciarCampos();
                    m.setCodigoMensaje(203);
                    m.setCifrado(resultado);

                    oos.writeObject(m);
                    oos.flush();
                    m = (Mensaje)ois.readObject();
                }
                case 104->{ //mensaje firmado
                    Signature signature = Signature.getInstance("SHA256withRSA");
                    signature.initVerify(clavePublicaCliente);

                    signature.update(m.getMensaje().getBytes());
                    boolean firma = signature.verify(m.getCifrado());

                    m.reiniciarCampos();
                    if(firma) {
                        m.setMensaje("El mensaje ha sido firmado con exito");
                    }else{
                        m.setMensaje("El mensaje no es de fiar");
                    }
                    m.setCodigoMensaje(501);

                    oos.writeObject(m);
                    oos.flush();
                    m = (Mensaje) ois.readObject();
                }
                case 105->{ //cifrado híbrido
                    Cipher cifrador = Cipher.getInstance(clavePrivada.getAlgorithm());
                    cifrador.init(Cipher.DECRYPT_MODE, clavePrivada);
                    byte[] resultadoClave = cifrador.doFinal(m.getClaveCifrada());

                    SecretKey pass = new SecretKeySpec(resultadoClave, "AES");

                    Cipher cifradorAES = Cipher.getInstance(pass.getAlgorithm());
                    cifradorAES.init(Cipher.DECRYPT_MODE, pass);
                    byte[] resultadoAES = cifrador.doFinal(m.getCifrado());

                    String mensaje = new String(resultadoAES, StandardCharsets.UTF_8);
                    String mensajeVuelta = "tengo tu clave, esta comunicación es segura y tu me enviaste " + mensaje;
                    cifradorAES.init(Cipher.ENCRYPT_MODE, pass);
                    resultadoAES = cifradorAES.doFinal(mensajeVuelta.getBytes());


                    m.reiniciarCampos();
                    m.setCodigoMensaje(204);
                    m.setCifrado(resultadoAES);

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
                    m.setCodigoMensaje(201);
                    m.setMensaje("No existe en el menu");

                    oos.writeObject(m);
                    oos.flush();
                    m = (Mensaje)ois.readObject();
                }
            }
        }while(cod != 0);

        // 8. Cerrar las conexiones
        socket.close();
        servidor.close();
        System.out.println("🔒 Conexión cerrada.");
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

    public static SecretKey claveSimetrica() throws NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        return kg.generateKey();
    }

    public static String conversor(byte[] ent){
        return String.format("%02x", new BigInteger(1, ent));
    }
}

