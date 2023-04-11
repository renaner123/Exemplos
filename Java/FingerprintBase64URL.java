import java.io.FileInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Classe com um exemplo de como calcular o fingerprint de um certificado X.509 e representa-ló em Base64URL
 */
public class ExemploFingerprintBase64URL {

    /**
     * Carrega um certificado digital
     * @param filename caminho onde está localizado o certificado
     * @return         certificado no formato X509Certificate
     * @throws Exception
     */
    private X509Certificate loadCertFromFile(String filename) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        FileInputStream in = new FileInputStream(filename);
        X509Certificate cert = (X509Certificate) cf.generateCertificate(in);
        in.close();
        return cert;
    }

    /**
     * Faz a representação de bytes[] para Base64URL
     * @param bytes conteúdo de entrada da função Base64URL
     * @return      string contendo a representação dos bytes em base64URL
     */
    private String bytesToBase64(byte[] bytes) {
        // Converte um array de bytes em uma string em representação Base64URL
        String fingerprintBase64 = Base64.getUrlEncoder().encodeToString(bytes);
        return fingerprintBase64;
    }    

    /**
     * Calcula o hash usando SHA-256 do certificado X509Certificate
     * @param cert certificado no formato X509Certificate
     * @return     o digest (fingerprint) do certificado em bytes
     * @throws CertificateEncodingException
     * @throws NoSuchAlgorithmException
     */
    private byte[] certDigest(X509Certificate cert) throws CertificateEncodingException, NoSuchAlgorithmException{
        byte[] certBytes = cert.getEncoded();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = md.digest(certBytes);
        return hashBytes;
    }
    
    public static void main(String[] args) throws Exception {

        ExemploFingerprintBase64URL fingerprint = new ExemploFingerprintBase64URL();

        // Carrega o certificado a partir de um arquivo
        X509Certificate cert = fingerprint.loadCertFromFile("sef-cert-ec.pem");

        // Calcula o hash SHA-256 do certificado
        byte[] certDigest = fingerprint.certDigest(cert);

        // Converte um array de bytes em Base64URL
        String fingerprintBase64 = fingerprint.bytesToBase64(certDigest);

        System.out.println("Fingerprint em Base64URL: " + fingerprintBase64);
    }
}
