import java.io.*;
import java.util.*;

/**
 * @Author Pycro
 * @Create 2023-03-13  23:33
 * @Description
 * @Version 1.0
 */
public class SwapCharCrypt {
    private static final Map<Character, Character>
            encryptMap = new HashMap<>(),
            decryptMap = new HashMap<>();

    private static final DynamicDESUtil DES = new DynamicDESUtil();


    // 生成秘钥
    public static void generateSK(long seed) {
        List<Character>
                encryptList = new ArrayList<>(),
                copyList = new ArrayList<>();
        // 添加小写字母
        for (int i = 0; i < 6; i++) {
            copyList.add((char) (i + 97));
            encryptList.add((char) (i + 97));
        }
        //添加数字
        for (int i = 0; i < 10; i++) {
            copyList.add((char) (i + 48));
            encryptList.add((char) (i + 48));
        }
        // 生成加密秘钥和解密秘钥的对称映射关系
        Collections.shuffle(encryptList, new Random(seed));
        for (int i = 0; i < encryptList.size(); i++) {
            encryptMap.put(copyList.get(i), encryptList.get(i));
            decryptMap.put(encryptList.get(i), copyList.get(i));
        }
    }

    // 加密or解密
    //public static String change(String srcText, int flag, long seed, String key) {
    //    generateSK(seed);
    //    String resultText = flag == 0 ? DES.encryption(srcText, key, seed) : DES.decryption(srcText, key, seed);
    //    StringBuilder targetText = new StringBuilder();
    //    Map<Character, Character> operateMap = flag == 0 ? encryptMap : decryptMap;
    //    for (int i = 0; i < resultText.length(); i++) targetText.append(operateMap.get(resultText.charAt(i)));
    //    return targetText.toString();
    //}

    //加密
    public static String encrypt(String srcText, long seed, String key) {
        generateSK(seed);
        String resultText = DES.encryption(srcText, key, seed);
        StringBuilder targetText = new StringBuilder();
        for (int i = 0; i < resultText.length(); i++) targetText.append(encryptMap.get(resultText.charAt(i)));
        return targetText.toString();
    }

    //解密
    public static String decrypt(String srcText, long seed, String key) {
        generateSK(seed);
        StringBuilder targetText = new StringBuilder();
        for (int i = 0; i < srcText.length(); i++) targetText.append(decryptMap.get(srcText.charAt(i)));
        return DES.decryption(targetText.toString(), key, seed);
    }

    // 文件操作————加密or解密
    public static void changeFile(String srcFile, String destFile, int flag, long seed, String key) throws IOException {
        BufferedReader br = null;
        BufferedWriter bw = null;
        try {
            // 补全扩展名
            if (!srcFile.contains(".txt")) srcFile += ".txt";
            if (!destFile.contains(".txt")) destFile += ".txt";
            // 创建文件和相应的流
            br = new BufferedReader(new FileReader(srcFile));
            bw = new BufferedWriter(new FileWriter(destFile));

            // 读写操作
            String data;
            while ((data = br.readLine()) != null) {
                data = flag == 0 ? encrypt(data, seed, key) : decrypt(data, seed, key);
                bw.write(data);
                bw.newLine();// 提供换行的操作
            }
        } finally {
            // 关闭资源
            try {
                if (bw != null) bw.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                if (br != null) br.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        System.out.printf("%s成功，文件%s已生成！", flag == 0 ? "加密" : "解密", destFile);
    }

}
