import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

/**
 * @Author Pycro
 * @Create 2023-03-13  23:46
 * @Description
 * @Version 1.0
 */
public class TestSDD {
    public static void main(String[] args) throws IOException {
        Scanner sc = new Scanner(System.in);
        System.out.print("输入0进行加密，输入1进行解密，请选择操作：");
        int flag = Integer.parseInt(sc.nextLine());
        if (flag != 0 && flag != 1) throw new RuntimeException("输入数据有误！");
        System.out.printf("请输入需要%s密的文件名:", flag == 0 ? "加" : "解");
        String srcFile = sc.nextLine();// 文件名
        System.out.print(flag == 0 ? "请输入一段字符作为加密秘钥（可选）：" : "请输入解密秘钥：");
        String input = sc.nextLine();
        long seed;
        if (flag == 0 && Objects.equals(input, "")) {//在选择加密的情况下不手动输入秘钥，则使用默认秘钥
            input = String.valueOf(System.currentTimeMillis());
            System.out.println("您选择了系统当前时间作为默认秘钥：" + input);
        }
        seed = str2long(input);
        System.out.print("请输入生成的文件名：");
        String destFile = sc.nextLine();
        String key = seed2Key(seed);
        SwapCharCrypt.changeFile(srcFile, destFile, flag, seed, key);// 操作
    }

    public static String seed2Key(long seed) {
        char[] sch = String.valueOf(seed).toCharArray();
        List<Character> scList = new ArrayList<>();
        for (char c : sch) scList.add(c);
        Collections.shuffle(scList, new Random(seed));
        StringBuilder builder = new StringBuilder();
        for (Character c : scList) builder.append(c);
        return builder.toString();
    }

    public static long str2long(String input) {
        byte[] chars = input.trim().getBytes();
        StringBuilder builder = new StringBuilder();
        for (byte ch : chars) builder.append(Math.abs(ch));
        BigInteger bigInt = new BigInteger(builder.toString());
        BigInteger longMax = BigInteger.valueOf(Long.MAX_VALUE);
        if (bigInt.compareTo(longMax) > 0) bigInt = bigInt.mod(longMax);
        return bigInt.longValue();
    }
}
