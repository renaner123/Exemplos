package Java;

import java.util.HashMap;
import java.util.Map;
import java.time.Duration;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import lombok.extern.slf4j.Slf4j;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.exceptions.JedisException;

@Slf4j
public class RedisClient {
    
    private static final String redisHost = "http://localhost";
    private static final String redisPort = "6379";
    

    final JedisPoolConfig poolConfig = buildPoolConfig();
    JedisPool jedisPool = new JedisPool(poolConfig, redisHost+":"+redisPort);
    
    
    /** 
     * @return JedisPoolConfig
     */
    private JedisPoolConfig buildPoolConfig() {
        final JedisPoolConfig poolConfig = new JedisPoolConfig();
        poolConfig.setMaxTotal(128);
        poolConfig.setMaxIdle(128);
        poolConfig.setMinIdle(16);
        poolConfig.setTestOnBorrow(true);
        poolConfig.setTestOnReturn(true);
        poolConfig.setTestWhileIdle(true);
        poolConfig.setNumTestsPerEvictionRun(3);
        poolConfig.setBlockWhenExhausted(true);
        poolConfig.setMinEvictableIdleTime(Duration.ofMillis(60000));
        poolConfig.setTimeBetweenEvictionRuns(Duration.ofMillis(30000));

        return poolConfig;
    } 

    /**
     * Método que recebe uma string contendo um Json e armazena no Redis como um hashmap
     * 
     * @param keyredis      chave onde o json será armazenado no redis
     * @param stringjson    string contendo o json a ser armazenado
     * @return              true se conseguir salvar, false se encontrar algum problema
     */
    public boolean addStringJsonToRedis(String keyredis, String stringjson){
        String key = keyredis;        
        Jedis jedis = jedisPool.getResource();

        Map<String, String> map = new Gson().fromJson(
            stringjson, new TypeToken<HashMap<String, Object>>() {}.getType()
        );
        try {
            jedis.hmset(key, map);
            return true;
 
        } catch (JedisException e) {
            if (null != jedis) {
                jedisPool.returnBrokenResource(jedis);
                jedis = null;
                log.error(e.getMessage());
            } 
        }
        return false;
    }

    /**
     * Método que recebe uma String contendo uma Key que está armazenada no Redis e 
     * retorna os campos em String no formato Json
     * 
     * @param keyredis  Chave onde está armazenado a String Json no Redis
     * @return          uma string no formato Json com os valores da chave
     */
    public String getStringJsonFromRedis(String keyredis){
        Jedis jedis = jedisPool.getResource();
        String jsonreturn = "";
        try {

            Map<String, String> retrieveMap = jedis.hgetAll(keyredis);
            Gson gson = new Gson(); 
            jsonreturn = gson.toJson(retrieveMap); 
 
        } catch (JedisException e) {

            if (null != jedis) {
                jedisPool.returnBrokenResource(jedis);
                jedis = null;
                log.error(e.getMessage());
            } 
        }finally {
            if (null != jedis)
            jedisPool.returnResource(jedis);
        }

        return jsonreturn;

    }

    /**
     * Método que retorna o valor contido na chave do "objeto" Json armazenado na chave redis.
     * 
     * @param keyredis  chave que está armazrnado a string json
     * @param keyjson   chave do Json que se deseja consultar o valor
     * @return          o valor da chave Json informada.
     */
    public String getValueFromKeyJsonRedis(String keyredis, String keyjson){
        Jedis jedis = jedisPool.getResource();
        try {

            Map<String, String> retrieveMap = jedis.hgetAll(keyredis);
            for (String keyMap : retrieveMap.keySet()) {
                if(keyMap.equals(keyjson))
                    return(retrieveMap.get(keyMap));
            }
 
        } catch (JedisException e) {

            if (null != jedis) {
                jedisPool.returnBrokenResource(jedis);
                jedis = null;
                log.error(e.getMessage());
            } 
        }finally {

            if (null != jedis)
            jedisPool.returnResource(jedis);
        }
        return "";
    }

    /**
     * Método para alterar um valor de uma chave Json armazenada em uma chave redis
     * 
     * @param keyredis  chave que está armazrnado a string json
     * @param keyjson   chave do Json que se deseja consultar o valor
     * @param newvalue  novo valor que a chave Json terá.
     * @return          true se conseguir alterar, false caso ocorra algum erro.
     */
    public boolean modifyValueFromKeyJsonRedis(String keyredis, String keyjson, String newvalue){
        Jedis jedis = jedisPool.getResource();
        try {
            Map<String, String> retrieveMap = jedis.hgetAll(keyredis);
            for (String keyMap : retrieveMap.keySet()) {
                if(keyMap.equals(keyjson))
                    retrieveMap.replace(keyMap, retrieveMap.get(keyMap), newvalue);
            }
            
            jedis.hmset(keyredis, retrieveMap);
            return true;

        } catch (JedisException e) {
            if (null != jedis) {
                jedisPool.returnBrokenResource(jedis);
                jedis = null;
                log.error(e.getMessage());
                return false;
            } 
        }finally {
            if (null != jedis)
            jedisPool.returnResource(jedis);
        }
        return false;
    }

    public boolean addSingleKeyValueInRedis(String keyredis, String value){
        Jedis jedis = jedisPool.getResource();

        try {            
            jedis.set(keyredis, value);
            return true;

        } catch (JedisException e) {
            if (null != jedis) {
                jedisPool.returnBrokenResource(jedis);
                jedis = null;
                log.error(e.getMessage());
                return false;
            } 
        }finally {
            if (null != jedis)
            jedisPool.returnResource(jedis);
        }

        return false;

    }

    public boolean addHashMapInRedis(String keyredis, Map<String, String> map){
        Jedis jedis = jedisPool.getResource();
        
        try {
            
            jedis.hmset(keyredis, map);
            return true;

        } catch (JedisException e) {
            if (null != jedis) {
                jedisPool.returnBrokenResource(jedis);
                jedis = null;
                log.error(e.getMessage());
            } 
        }finally {
            if (null != jedis)
            jedisPool.returnResource(jedis);
        }
        return false;

    }

    public Map<String,String> getHasMapFromRedis(String keyredis){
        Jedis jedis = jedisPool.getResource();

        try {
            
            Map<String, String> retrieveMap = jedis.hgetAll(keyredis);
            return retrieveMap;
            
        } catch (JedisException e) {
            if (null != jedis) {
                jedisPool.returnBrokenResource(jedis);
                jedis = null;
                log.error(e.getMessage());
            } 
        }finally {
            if (null != jedis)
            jedisPool.returnResource(jedis);
        }
        return null;

    }

    
    public static void main(String[] args) {
        RedisClient main = new RedisClient();
        String key = "KeyRedis";
        String jsoninfo = "{\"path\":\"abcd1234\",\"id\":\"123asd123\",\"nnc\":\"123sdfsdfasd123\"}";
        main.addStringJsonToRedis(key,jsoninfo);

        String jsonfromredis = main.getStringJsonFromRedis(key);

        System.out.println(jsonfromredis+"\n");

        System.out.println(main.getValueFromKeyJsonRedis(key, "path"));
   
        main.modifyValueFromKeyJsonRedis(key, "path", "123456789abcd");

        System.out.println(main.getValueFromKeyJsonRedis(key, "path"));


        
        Map<String,String> example = new HashMap<String,String>();

        example.put( "path", new String( "V1bsdv123" ));  
        example.put( "path", new String( "V1sdfsa123" ));  
        example.put( "chave1", new String( "adf#asdf#" ));  
        example.put( "chave2", new String( "V123123" ));  

        main.addHashMapInRedis("example", example);

        String examplejson = main.getStringJsonFromRedis("example");

        System.out.println(examplejson);

        System.out.println(main.getValueFromKeyJsonRedis("example", "path"));

        main.addSingleKeyValueInRedis("renan","");


        Map<String,String> jsontohash = main.getHasMapFromRedis("KeyRedis");

        System.out.println(jsontohash.get("path"));
    }

}
