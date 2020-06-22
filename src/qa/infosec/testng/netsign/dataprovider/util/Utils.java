package qa.infosec.testng.netsign.dataprovider.util;

import cn.com.infosec.asn1.x509.X509NameTokenizer;
import cn.com.infosec.jce.provider.InfosecProvider;
import cn.com.infosec.netsign.crypto.util.Base64;
import cn.com.infosec.netsign.json.JsonObject;
import cn.com.infosec.netsign.json.JsonParser;
import org.testng.Assert;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Random;

/**
 * DN倒序、获取随机数
 * <p>Title: Utils</p>
 * <p>Description: </p>
 *
 * @author maxf
 * @date 2019年8月15日
 */
public class Utils {

    static {
        Security.addProvider(new InfosecProvider());
    }

    private static final String[] dNObjectsForward = {
            "1.2.840.113549.1.9.8", "1.2.840.113549.1.9.2", "emailaddress", "e", "email", "uid", "cn", "sn",
            "serialnumber", "gn", "givenname",
            "initials", "surname", "t", "ou", "o", "l", "st", "dc", "c"
    };
    private static final String[] dNObjects = dNObjectsForward;

    public static String getDN(int order, String dn) {
        if ((dn == null) || "".equals(dn)) {
            return dn;
        }
        // 配置DN的顺序，0：自然顺序，1:CN在最前，2：CN在最后
        switch (order) {
            case 0:
                return dn;
            case 1:
                if (isDNReversed(dn)) {
                    return reverseDN(dn);
                } else {
                    return dn;
                }
            case 2:
                if (dn.startsWith("CN=") || dn.startsWith("cn=")) {
                    return turnDNString(dn);
                } else {
                    return dn;
                }
            default:
                break;
        }
        return dn;
    }

    public static String setReverseDN(String dn) {
        if (dn.startsWith("CN=") || dn.startsWith("cn=")) {
            return turnDNString(dn);
        } else {
            return reverseDN(dn);
        }
    }

    private static String turnDNString(String dn) {
        if (dn.contains(",")) {
            String split = (", ".contains(dn)) ? ", " : "{2},";
            String[] pieces = dn.split(split);
            StringBuilder tmp = new StringBuilder();
            for (int i = pieces.length - 1; i >= 0; i--) {
                tmp.append(pieces[i]);
                if (i != 0) {
                    tmp.append(split);
                }
            }
            return tmp.toString();
        } else {
            return dn;
        }
    }

    public static boolean isDNReversed(String dn) {
        boolean ret = false;
        if (dn != null) {
            String first = null;
            String last = null;
            X509NameTokenizer xt = new X509NameTokenizer(dn);
            if (xt.hasMoreTokens()) {
                first = xt.nextToken();
            }
            while (xt.hasMoreTokens()) {
                last = xt.nextToken();
            }
            if ((first != null) && (last != null)) {
                first = first.substring(0, first.indexOf('='));
                last = last.substring(0, last.indexOf('='));
                int firsti = 0, lasti = 0;
                for (int i = 0; i < dNObjects.length; i++) {
                    if (first.toLowerCase().equals(dNObjectsForward[i])) {
                        firsti = i;
                    }
                    if (last.toLowerCase().equals(dNObjectsForward[i])) {
                        lasti = i;
                    }
                }
                if (lasti < firsti) {
                    ret = true;
                }

            }
        }
        return ret;
    }

    public static String reverseDN(String dn) {
        String ret = null;
        if (dn != null) {
            String o;
            BasicX509NameTokenizer xt = new BasicX509NameTokenizer(dn);
            StringBuilder buf = new StringBuilder();
            boolean first = true;
            while (xt.hasMoreTokens()) {
                o = xt.nextToken();
                // log.debug("token: "+o);
                if (!first) {
                    buf.insert(0, ",");
                } else {
                    first = false;
                }
                buf.insert(0, o);
            }
            if (buf.length() > 0) {
                ret = buf.toString();
            }


        }
        return ret;
    } // reverseDN

    private static class BasicX509NameTokenizer {
        private String oid;
        private int index;
        private StringBuffer buf = new StringBuffer();

        public BasicX509NameTokenizer(String oid) {
            this.oid = oid;
            this.index = -1;
        }

        public boolean hasMoreTokens() {
            return (index != oid.length());
        }

        public String nextToken() {
            if (index == oid.length()) {
                return null;
            }

            int end = index + 1;
            boolean quoted = false;
            boolean escaped = false;

            buf.setLength(0);

            while (end != oid.length()) {
                char c = oid.charAt(end);

                if (c == '"') {
                    buf.append(c);
                    if (!escaped) {
                        quoted = !quoted;
                    }
                    escaped = false;
                } else {
                    if (escaped || quoted) {
                        buf.append(c);
                        escaped = false;
                    } else if (c == '\\') {
                        buf.append(c);
                        escaped = true;
                    } else if (c == ',') {
                        break;
                    } else {
                        buf.append(c);
                    }
                }
                end++;
            }

            index = end;
            return buf.toString().trim();
        }
    }

    public static String getRandomString(int length) {
        // 1. 定义一个字符串（A-Z，a-z，0-9）即62个数字字母；
        String str = "1234567890";
        // 2. 由Random生成随机数
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        // 3. 长度为几就循环几次
        for (int i = 0; i < length; ++i) {
            // 从62个的数字或字母中选择
            int number = random.nextInt(10);
            // 将产生的数字通过length次承载到sb中
            sb.append(str.charAt(number));
        }
        // 将承载的字符转换成字符串
        return sb.toString();
    }

    /**
     * 制作摘要
     *
     * @param plainText 原文数据
     * @param algType   摘要算法类型
     * @return 摘要结果
     */
    public static byte[] getDigest(String algType, byte[] plainText) {
        if (plainText != null) {
            byte[] digest = null;
            try {
                MessageDigest md = MessageDigest.getInstance(algType);
                digest = md.digest(plainText);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            return digest;
        } else {
            Assert.fail("请正确输入参数");
            return null;
        }
    }


    /**
     * 将BigInteger类型转换为String
     *
     * @param integer value
     * @return String value
     */
    public static String biginter2HexString(BigInteger integer) {
        byte[] bs = integer.toByteArray();
        return toHexString(bs);
    }

    /**
     * 将byte[]类型数据转换为16进制String类型数据
     *
     * @param bs byte[] value
     * @return String value
     */
    public static String toHexString(byte[] bs) {
        StringBuilder buf = new StringBuilder();
        int i = 0;

        for (int length = bs.length; i < length; ++i) {
            int x = bs[i] & 255;
            if (x == 0) {
                buf.append("00");
            } else {
                String hex = Integer.toHexString(x);
                hex = hex.length() % 2 == 0 ? hex : "0" + hex;
                buf.append(hex);
            }
        }

        return buf.toString();
    }

    /**
     * 修改String类型数据，用于篡改密文
     *
     * @param plainText 原文
     * @param a         起始位置
     * @param b         终止位置
     * @param data      要修改的内容
     * @return 修改后的数据
     */
    public static String modifyData(String plainText, int a, int b, String data) {
        StringBuilder stringBuilder = new StringBuilder(plainText);
        stringBuilder.replace(a, b, data);
        plainText = new String(stringBuilder);
        return plainText;
    }

    /**
     * 修改byte[]类型数据，用于篡改密文
     *
     * @param plainText 原文
     * @param a         起始位置
     * @param b         终止位置
     * @param data      要修改的内容
     * @return 修改后的数据
     */
    public static byte[] modifyData(byte[] plainText, int a, int b, String data) {
        String encode_text = Base64.encode(plainText);
        StringBuilder stringBuilder = new StringBuilder(encode_text);
        stringBuilder.replace(a, b, data);
        encode_text = stringBuilder.toString();
        String encode_text1 = new String(stringBuilder);
        plainText = Base64.decode(encode_text);
        return plainText;
    }

    /**
     * 将16进制String类型数据转换为byte[]
     *
     * @param hex value
     * @return [byte[] value]
     */
    public static byte[] hexString2ByteArray(String hex) {
        hex = formatHexString(hex);
        byte[] bs = hex.length() % 2 == 0 ? new byte[hex.length() / 2] : new byte[hex.length() / 2 + 1];

        for (int i = bs.length - 1; i > -1; --i) {
            String strb = hex.substring(i * 2, i * 2 + 2);
            bs[i] = (byte) (Integer.parseInt(strb, 16) & 255);
        }

        return bs;
    }

    private static String formatHexString(String hex) {
        hex = hex.trim().replaceAll("0x", "").toUpperCase();
        StringBuilder builder = new StringBuilder();
        char[] chars = hex.toCharArray();

        for (char aChar : chars) {
            if (aChar >= '0' && aChar <= '9' || aChar >= 'A' && aChar <= 'F') {
                builder.append(aChar);
            }
        }

        return builder.toString();
    }

    /**
     * 读取jsonMessage信息，返回JsonObject对象
     *
     * @param jsonMessage json信息
     * @return JsonObject对象
     */
    public static JsonObject getJsonObject(String jsonMessage) {
        JsonObject jsonObject;
        JsonParser jsonParser = new JsonParser("utf-8");

        try {
            jsonObject = jsonParser.parse(jsonMessage.toCharArray());
            return jsonObject;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }



    public static void main(String[] args) {
        byte[] sha1s = getDigest("SM3", Utils.getRandomString(1024).getBytes());
        String encode = Base64.encode(sha1s);
        System.out.println(encode);
        String s = Utils.toHexString(Base64.decode(encode));
        System.out.println(s);


    }
}
