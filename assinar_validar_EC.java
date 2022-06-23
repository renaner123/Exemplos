import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.OutputStream;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Scanner;

/**
 * Classe com um exemplo de como gerar par de chaves RSA, assinar uma String e
 * verificar a assinatura usando esquema SHA256withRSA
 * 
 * Para efeitos de simplificação essa classe não tratou nenhuma exceção e não
 * verifica se haverá sobreescrita de arquivos em disco.
 * 
 * @author Emerson Ribeiro de Mello
 */
public class ExemploAssinaturasRsa {

    private PrivateKey privKey;
    private PublicKey pubKey;

    public ExemploAssinaturasRsa() throws Exception {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096);

        // gerando o par de chaves RSA
        KeyPair parDeChaves = kpg.generateKeyPair();
        this.privKey = parDeChaves.getPrivate();
        this.pubKey = parDeChaves.getPublic();
    }

    public void exportarChavesEmBase64(String nomeDoArquivo) throws Exception {

        Base64.Encoder encoder = Base64.getEncoder();

        // chave privada
        System.out.println("Chave privada no formato: " + this.privKey.getFormat());
        Writer out = new FileWriter(nomeDoArquivo + ".key");
        out.write("-----BEGIN RSA PRIVATE KEY-----\n");
        out.write(encoder.encodeToString(this.privKey.getEncoded()));
        out.write("\n-----END RSA PRIVATE KEY-----\n");
        out.close();

        // chave pública
        System.out.println("Chave pública no format: " + this.pubKey.getFormat());
        out = new FileWriter(nomeDoArquivo + ".pub");
        out.write("-----BEGIN RSA PUBLIC KEY-----\n");
        out.write(encoder.encodeToString(this.pubKey.getEncoded()));
        out.write("\n-----END RSA PUBLIC KEY-----\n");
        out.close();
    }

    /**
     * Assinar conteudo com o esquema SHA256withRSA
     * 
     * @param conteudo conteúdo a ser assinado
     * @return assinatura em Base64
     */
    public byte[] assinar(byte[] conteudo, String nomeDoArquivoComAssinatura, PrivateKey chave) throws Exception {
        Signature signature = Signature.getInstance("SHA384withECDSA");
        signature.initSign(chave);

        signature.update(conteudo);

        byte[] assinatura = signature.sign();

        // salvando assinatura no arquivo
        if (nomeDoArquivoComAssinatura != null) {
            OutputStream out = new FileOutputStream(nomeDoArquivoComAssinatura);
            out.write(assinatura);
            out.close();
        }

        return assinatura;
    }

    /**
     * Verifica se a assinatura é válida
     * 
     * @param assinaturaEmBase64 assinatura no formato textual Base64
     * @return
     */
    public String verificarAssinatura(String conteudoAssinado, String nomeDoArquivoComAssinatura, PublicKey pub_key)
            throws Exception {

        // Carregando chave pública
        Signature signature = Signature.getInstance("SHA384withECDSA");
        signature.initVerify(pub_key);

        // Carregando conteúdo que foi assinado
        signature.update(conteudoAssinado.getBytes("UTF-8"));

        // Carregando assinatura do arquivo
        Path path = Paths.get(nomeDoArquivoComAssinatura);
        byte[] signBytes = Files.readAllBytes(path);

        return signature.verify(signBytes) ? "Assinatura válida" : "Assinatura não está válida";
    }

    public PrivateKey getKeyPrivateFromFile(String caminho, String algoritmo) throws Exception {

        String chave = getStringKeyFromFile(caminho);
        PrivateKey sefPrivKey = (PrivateKey) stringToKeyPrivada(chave, algoritmo);
        return sefPrivKey;

    }

    public Key stringToKeyPrivada(String chave, String algoritmo)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        chave = chave.replace("-----BEGIN PRIVATE KEY-----", "");
        chave = chave.replace("-----END PRIVATE KEY-----", "");
        chave = chave.replaceAll("\\n", "");

        byte[] tobyte = Base64.getDecoder().decode(chave);

        KeyFactory kf;

        kf = KeyFactory.getInstance("EC");

        return kf.generatePrivate(new PKCS8EncodedKeySpec(tobyte));
    }

    public static String getStringKeyFromFile(String caminho) throws Exception {

        File keyfile = new File(caminho);
        // String absolute = keyfile.getAbsolutePath();
        // TODO achar uma forma melhor de ler o arquivo
        String chavestring = new Scanner(keyfile).useDelimiter("\\A").next();

        return chavestring;

    }

    public Key stringToKeyPublic(String chave, String algoritmo)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        chave = chave.replace("-----BEGIN PUBLIC KEY-----", "");
        chave = chave.replace("-----END PUBLIC KEY-----", "");
        chave = chave.replaceAll("\\n", "");
        byte[] tobyte = Base64.getDecoder().decode(chave);

        KeyFactory kf;
        if ((algoritmo).equals("ES384"))
            kf = KeyFactory.getInstance("EC");
        else
            kf = KeyFactory.getInstance("RSA");

        return kf.generatePublic(new X509EncodedKeySpec(tobyte));
    }

    public static void main(String[] args) throws Exception {

        String conteudoASerAssinado = "Ola mundo";
        String nomeDoArquivoComAssinatura = "assinatura-gerada.bin";

        ExemploAssinaturasRsa assinador = new ExemploAssinaturasRsa();

        File keyfilePublic = new File("/home/renan/Documentos/Testes/Java/sef-pub-ec.pem");
        String chavePublica = new Scanner(keyfilePublic).useDelimiter("\\A").next();


        PrivateKey sefPrivKey = assinador.getKeyPrivateFromFile("/home/renan/Documentos/Testes/Java/sef-private.pem",
                "ES384");

        Key key_public_sef = assinador.stringToKeyPublic(chavePublica,"ES384"); 

        assinador.assinar(conteudoASerAssinado.getBytes("UTF-8"), nomeDoArquivoComAssinatura, sefPrivKey);

        System.out.println(assinador.verificarAssinatura(conteudoASerAssinado, "/home/renan/Documentos/Testes/Java/assinatura-gerada.bin",(PublicKey) key_public_sef));
        

        // Para exportar o par de chaves como arquivos
        // // Assinando
        // byte[] assinatura = assinador.assinar(conteudoASerAssinado.getBytes("UTF-8"),
        // nomeDoArquivoComAssinatura);
        // System.out.println("Assinatura em Base64 ["+ assinatura.length + " bits]: "+
        // Base64.getEncoder().encodeToString(assinatura) + "\n");

        // // Verificando assinatura
        // System.out.println(assinador.verificarAssinatura(conteudoASerAssinado,
        // nomeDoArquivoComAssinatura));
    }
}
