package Java;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class ExtrairKey {

    public ExtrairKey() {
    }
    private String Path_keystore_cont = "key-rsa-4096.pkcs12";
    private String Alias = "1";
    private String Pass_private_key = "123456";
    private String Pass_keystore = "123456";
    private String type_keystore = "PKCS12";
    X509Certificate cert = null;
    Key privateKey = null;
    PublicKey publicKey = null;
    

    public String getPath_keystore_cont() {
        return Path_keystore_cont;
    }

    public void setPath_keystore_cont(String path_keystore_cont) {
        Path_keystore_cont = path_keystore_cont;
    }

    public String getAlias() {
        return Alias;
    }

    public void setAlias(String alias) {
        Alias = alias;
    }

    public String gettPass_private_key() {
        return Pass_private_key;
    }

    public void settPass_private_key(String tPass_private_key) {
        this.Pass_private_key = tPass_private_key;
    }

    public String getPass_keystore() {
        return Pass_keystore;
    }

    public void setPass_keystore(String pass_keystore) {
        Pass_keystore = pass_keystore;
    }

    public String getType_keystore() {
        return type_keystore;
    }

    public void setType_keystore(String type_keystore) {
        this.type_keystore = type_keystore;
    }
    

    public X509Certificate getCert() {
        return cert;
    }

    public void setCert(X509Certificate cert) {
        this.cert = cert;
    }

    public Key getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(Key privateKey) {
        this.privateKey = privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public void getKeys() {

        InputStream reader = null;
        try {
            reader = new FileInputStream(this.getPath_keystore_cont());
            KeyStore ks = KeyStore.getInstance(this.getType_keystore());
            ks.load(reader, this.getPass_keystore().toCharArray());
            KeyStore.PrivateKeyEntry keyEntry;
            keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(this.getAlias(), new KeyStore.PasswordProtection(this.gettPass_private_key().toCharArray()));
            this.cert = (X509Certificate) keyEntry.getCertificate();
            this.privateKey = keyEntry.getPrivateKey();
            this.publicKey = cert.getPublicKey();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    public void exportarChavesEmBase64(String nomeDoArquivo) throws Exception{
        
        Base64.Encoder encoder = Base64.getEncoder();

        // chave privada
        System.out.println("Chave privada no formato: " +  this.privateKey.getFormat());
        Writer out = new FileWriter(nomeDoArquivo + ".key");
        out.write("-----BEGIN RSA PRIVATE KEY-----\n");
        out.write(encoder.encodeToString(this.privateKey.getEncoded()));
        out.write("\n-----END RSA PRIVATE KEY-----\n");
        out.close();

        // chave pública
        System.out.println("Chave pública no format: " +  this.publicKey.getFormat());
        out = new FileWriter(nomeDoArquivo + ".pub");
        out.write("-----BEGIN RSA PUBLIC KEY-----\n");
        out.write(encoder.encodeToString(this.publicKey.getEncoded()));
        out.write("\n-----END RSA PUBLIC KEY-----\n");
        out.close();

        // Certificado
        out = new FileWriter("certificado" + ".pem");
        out.write("-----BEGIN CERTIFICATE-----\n");
        out.write(encoder.encodeToString(this.cert.getEncoded()));
        out.write("\n-----END CERTIFICATE-----\n");
        out.close();
    }
    public static void main(String[] args) throws Exception {

        ExtrairKey teste = new ExtrairKey();

        teste.getKeys();

        teste.exportarChavesEmBase64("sef");

    }
}
