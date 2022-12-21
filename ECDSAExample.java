package Assinatura;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.FileOutputStream;
import java.util.Scanner;

public class ECDSAExample {

    public ECDSAExample (){
        
    }    
    
    /**
     * 
     * @param caminho    caminho onde está a chave privada no formato EC
     * @param algoritmo  Algoritimo da chave ES256, ES348 ou ES512
     * @return           uma chave privada
     * @throws Exception
     */
    public PrivateKey getKeyPrivateFromFile(String caminho, String algoritmo) throws Exception {

        String chave = getStringKeyFromFile(caminho);
        PrivateKey sefPrivKey = (PrivateKey) stringToKeyPrivada(chave, algoritmo);
        return sefPrivKey;

    }
    // método interno -  Auxilia na leitura de uma chave do arquivo
    public String getStringKeyFromFile(String caminho) throws Exception {

        File keyfile = new File(caminho);
        String chavestring = new Scanner(keyfile).useDelimiter("\\A").next();

        return chavestring;

    }
    // método interno - converte uma chave no formato string para chave privada
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
    /**
     * 
     * @param conteudoAssinado      conteudo que foi assinado
     * @param arquivoComAssinatura  assinatura que foi gerada sobre o conteudo assinado
     * @param pub_key               chave que vai ser usada para validar a assinatura
     * @return
     * @throws Exception
     */  
    public String verificarAssinatura(byte[] conteudoAssinado, byte[] arquivoComAssinatura, PublicKey pub_key)
            throws Exception {

        // Carregando chave pública
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(pub_key);

        // Carregando conteúdo que foi assinado
        signature.update(conteudoAssinado);

        // Carregando assinatura do arquivo
        //Path path = Paths.get(nomeDoArquivoComAssinatura);
        byte[] signBytes = arquivoComAssinatura;

        return signature.verify(signBytes) ? "Assinatura válida" : "Assinatura não está válida";
    }

    /**
     * 
     * @param chave      caminho onde está a chave pública no formato EC
     * @param algoritmo  Algoritimo da chave ES256, ES348 ou ES512
     * @return
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    public Key stringToKeyPublic(String chave, String algoritmo)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        chave = chave.replace("-----BEGIN PUBLIC KEY-----", "");
        chave = chave.replace("-----END PUBLIC KEY-----", "");
        chave = chave.replaceAll("\\n", "");
        byte[] tobyte = Base64.getDecoder().decode(chave);

        KeyFactory kf;
        if ((algoritmo).equals(algoritmo))
            kf = KeyFactory.getInstance("EC");
        else
            kf = KeyFactory.getInstance("RSA");

        return kf.generatePublic(new X509EncodedKeySpec(tobyte));
    }


     // Método para fazer os testes
    public static void main(String[] args) throws Exception {

        String caminhoChavePrivada = "";

        // if(args.length < 1){
        //     System.out.println("Informe o caminho da chave privada");
        //     System.exit(0);
        // }else{
        //     caminhoChavePrivada = args[0];
        // }

        // Instancia a classe de teste
        ECDSAExample assinador = new ECDSAExample();

        // FIXME alterar o caminho da chave privada
        // chave privada que vai ser usada para gerar a assinatura.
        PrivateKey sefPrivKey = assinador.getKeyPrivateFromFile("Assinatura/priv-pkcs.pem", "ES512");    

        // instancia o algoritmo da assinatura que vai ser usada
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");

        ecdsa.initSign(sefPrivKey);

        // conteudo que vai ser assinado representado em hexadecimal
        String conteudoHex = "020900aef1cd3580a5d7ab300a06082a8648ce3d040302306a310b3009060355040613024252310b300906035504080c0253433111300f06035504070c0853616f204a6f7365310e300c060355040a0c054c61534544310d300b060355040b0c0449465343311c301a06035504030c13312e6c617365642e696673632e6564752e62723020170d3232313231313232323832375a180f33303232303431333232323832375a306a310b3009060355040613024252310b300906035504080c0253433111300f06035504070c0853616f204a6f7365310e300c060355040a0c054c61534544310d300b060355040b0c0449465343311c301a06035504030c13312e6c617365642e696673632e6564752e627230819b301006072a8648ce3d020106052b810400230381860004000898347568ae0c703c860cda0d945a578e638e09953f8d13c99bb91dedad57e2f601434e84454294412cad8d1f19d25a5cd4239b1b4ce4e9c9c4d35edec33aaef60191942191c4bab386284b24a1350d19050b89ff16472ce16a35c0104c8f077873bb1d7adb0165878639e820156d25532e634db1c0672fe63d519f560f97bf3f372b";

        //Converte a string que contem o hexadecimal para bytes
        byte[] conteudoBytes = new BigInteger(conteudoHex, 16).toByteArray(); 

        // carrega o conteudo que vai ser assinado
        ecdsa.update(conteudoBytes);

        // gera a assinatura
        byte[] realSig = ecdsa.sign();
        System.out.println(realSig.length);

        // java.io.File file = new java.io.File("Assinatura/cadeia-bytes.bin");
        // FileOutputStream in = new FileOutputStream(file) ;  
        // in.write(conteudoBytes);
        // in.close();

        // file = new java.io.File("Assinatura/assinatura.bin");
        // in = new FileOutputStream(file) ;  
        // in.write(realSig);
        // in.close();
        
        System.out.println("Assinatura em Base64UL: " + "\n" + Base64.getUrlEncoder().encodeToString(realSig)+ "\n");
        //System.out.println(realSig.length);

        
        // Path caminho = Paths.get("hash.sha256");

        // byte [] fileData = Files.readAllBytes(caminho);

        //System.out.println(fileData.length);

        
        //INFO Caso queira validar a assinatura, informar o caminho da chave pública e descomentar o trecho abaixo
        File keyfilePublic = new File("Assinatura/pub-pkcs.pem");
        String chavePublica = new Scanner(keyfilePublic).useDelimiter("\\A").next();
        Key key_public_sef = assinador.stringToKeyPublic(chavePublica,"ES512"); 
        System.out.println(assinador.verificarAssinatura(conteudoBytes, realSig, (PublicKey) key_public_sef));


        //openssl dgst -sha256 -sign Assinatura/priv-pkcs.pem -out hash.sha256 Assinatura/cadeia-bytes.bin


    }
}
