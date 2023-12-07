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

/**
    * Builds the JedisPoolConfig object with the specified configuration settings.
    * 
    * @return the JedisPoolConfig object
    */
@Slf4j
public class RedisClient {
    
    private static final String redisHost = "http://localhost";
    private static final String redisPort = "6379";
    

    final JedisPoolConfig poolConfig = buildPoolConfig();
    JedisPool jedisPool = new JedisPool(poolConfig, redisHost+":"+redisPort);
    
    

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
     * Adds a JSON string to Redis with the specified key.
     * 
     * @param keyredis the key to store the JSON string in Redis
     * @param stringjson the JSON string to be stored in Redis
     * @return true if the JSON string was successfully added to Redis, false otherwise
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
     * Retrieves a JSON string from Redis based on the given key.
     * 
     * @param keyredis the key used to retrieve the JSON string from Redis
     * @return the JSON string retrieved from Redis
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
     * Retrieves the value associated with a specific key in a Redis hash map, given the key of the hash map and the key of the JSON object within the hash map.
     * 
     * @param keyredis the key of the Redis hash map
     * @param keyjson the key of the JSON object within the hash map
     * @return the value associated with the specified key, or an empty string if the key is not found or an error occurs
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
     * Modifies the value associated with a specific key in a Redis hash map, given the key of the hash map, the key of the JSON object, and the new value.
     * 
     * @param keyredis the key of the Redis hash map
     * @param keyjson the key of the JSON object within the hash map
     * @param newvalue the new value to be set
     * @return true if the value was successfully modified, false otherwise
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

    /**
     * Adds a single key-value pair to Redis.
     * 
     * @param keyredis the key to be added
     * @param value the value associated with the key
     * @return true if the key-value pair was successfully added, false otherwise
     */
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

    /**
     * Adds a HashMap to Redis with the specified key and map.
     * 
     * @param keyredis the key to associate with the HashMap in Redis
     * @param map the HashMap to be added to Redis
     * @return true if the HashMap was successfully added to Redis, false otherwise
     */
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

    /**
     * Retrieves a HashMap from Redis based on the given key.
     * 
     * @param keyredis the key used to retrieve the HashMap from Redis
     * @return the retrieved HashMap from Redis, or null if an error occurs
     */
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
