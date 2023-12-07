package Java;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;

import br.edu.ifsc.lased.daf.sefapi.utils.ChavesUtil;
import br.edu.ifsc.lased.daf.sefapi.utils.GeradorUtil;

/**
 * This class represents an example of HMAC (Hash-based Message Authentication Code) implementation in Java.
 * It provides a method to test the HMAC functionality.
 */
public class Hmac {

    public boolean testHmac() throws JoseException, InvalidKeySpecException, NoSuchAlgorithmException {
        String nonce = "abcdef";
        String tkDesafio = "";

        String chaveSEF = "0-wBDvl-629U3r8p7wZfIH-vJ-tS-hIfBdMFIPoD7rKvN5AkhsgxgkUVc-e_vk2uzANuxtql-X9MC2dWrLC6Rg";


        JwtClaims payload = new JwtClaims();
        payload.setClaim("nnc", "_f_PmZ66L76JFw6WYYmF8w");
        payload.setClaim("daf", "lmo_4qSJQdKsSagASPuAhQ");
        payload.setClaim("cnt", "0");
        
        tkDesafio = ChavesUtil.gerarJWTHS256ChaveSef(chaveSEF, payload);
        System.out.println(tkDesafio);

        Key chaveSefHmac = new HmacKey(Base64.getUrlDecoder().decode(chaveSEF));

        JsonWebSignature jsonWebSignature = new JsonWebSignature();
        jsonWebSignature.setCompactSerialization(tkDesafio);
        jsonWebSignature.setKey(chaveSefHmac);
        boolean validacaoAssinatura = jsonWebSignature.verifySignature();

        return validacaoAssinatura;

    }
   
    public static void main(String[] args) throws JoseException, InvalidKeySpecException, NoSuchAlgorithmException {
        Hmac hmac = new Hmac();

        System.out.println(hmac.testHmac());
    }
    
}
