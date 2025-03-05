package data;

import javax.crypto.SecretKey;
import java.io.Serializable;
import java.security.PublicKey;

public class Mensaje implements Serializable {
    private int codigoMensaje = 201;
    private String mensaje = "";
    private SecretKey claveSimetrica = null;
    private byte[] cifrado = null;
    private byte[] claveCifrada = null;
    private PublicKey clavePublicaServidor = null;
    private PublicKey clavePublicaCliente = null;


    public Mensaje() {
    }

    //constructor de comunicacion
    public Mensaje(int cod, String mensaje) {
        this.codigoMensaje = cod;
        this.mensaje = mensaje;
    }

    //constructor completo
    public Mensaje(int codigoMensaje, String mensaje, SecretKey claveSimetrica, PublicKey clavePublica) {
        this.codigoMensaje = codigoMensaje;
        this.mensaje = mensaje;
        this.claveSimetrica = claveSimetrica;
        this.cifrado = cifrado;
        this.clavePublicaServidor = clavePublica;
    }

    public int getCodigoMensaje() {
        return codigoMensaje;
    }

    public void setCodigoMensaje(int codigoMensaje) {
        this.codigoMensaje = codigoMensaje;
    }

    public String getMensaje() {
        return mensaje;
    }

    public void setMensaje(String mensaje) {
        this.mensaje = mensaje;
    }

    public SecretKey getClaveSimetrica() {
        return claveSimetrica;
    }

    public void setClaveSimetrica(SecretKey claveSimetrica) {
        this.claveSimetrica = claveSimetrica;
    }

    public byte[] getCifrado() {
        return cifrado;
    }

    public void setCifrado(byte[] cifrado) {
        this.cifrado = cifrado;
    }

    public PublicKey getClavePublicaServidor() {
        return clavePublicaServidor;
    }

    public void setClavePublicaServidor(PublicKey clavePublicaServidor) {
        this.clavePublicaServidor = clavePublicaServidor;
    }

    public PublicKey getClavePublicaCliente() {
        return clavePublicaCliente;
    }

    public void setClavePublicaCliente(PublicKey clavePublicaCliente) {
        this.clavePublicaCliente = clavePublicaCliente;
    }


    public void reiniciarCampos(){
        codigoMensaje = 201;
        mensaje = "";
        claveSimetrica = null;
        cifrado = null;
        claveCifrada = null;
        clavePublicaServidor = null;
        clavePublicaCliente = null;
    }

    public byte[] getClaveCifrada() {
        return claveCifrada;
    }

    public void setClaveCifrada(byte[] claveCifrada) {
        this.claveCifrada = claveCifrada;
    }
}
