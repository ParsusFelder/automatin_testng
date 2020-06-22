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
 * DN���򡢻�ȡ�����
 * <p>Title: Utils</p>
 * <p>Description: </p>
 *
 * @author maxf
 * @date 2019��8��15��
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
        // ����DN��˳��0����Ȼ˳��1:CN����ǰ��2��CN�����
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
        // 1. ����һ���ַ�����A-Z��a-z��0-9����62��������ĸ��
        String str = "1234567890";
        // 2. ��Random���������
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        // 3. ����Ϊ����ѭ������
        for (int i = 0; i < length; ++i) {
            // ��62�������ֻ���ĸ��ѡ��
            int number = random.nextInt(10);
            // ������������ͨ��length�γ��ص�sb��
            sb.append(str.charAt(number));
        }
        // �����ص��ַ�ת�����ַ���
        return sb.toString();
    }

    /**
     * ����ժҪ
     *
     * @param plainText ԭ������
     * @param algType   ժҪ�㷨����
     * @return ժҪ���
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
            Assert.fail("����ȷ�������");
            return null;
        }
    }


    /**
     * ��BigInteger����ת��ΪString
     *
     * @param integer value
     * @return String value
     */
    public static String biginter2HexString(BigInteger integer) {
        byte[] bs = integer.toByteArray();
        return toHexString(bs);
    }

    /**
     * ��byte[]��������ת��Ϊ16����String��������
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
     * �޸�String�������ݣ����ڴ۸�����
     *
     * @param plainText ԭ��
     * @param a         ��ʼλ��
     * @param b         ��ֹλ��
     * @param data      Ҫ�޸ĵ�����
     * @return �޸ĺ������
     */
    public static String modifyData(String plainText, int a, int b, String data) {
        StringBuilder stringBuilder = new StringBuilder(plainText);
        stringBuilder.replace(a, b, data);
        plainText = new String(stringBuilder);
        return plainText;
    }

    /**
     * �޸�byte[]�������ݣ����ڴ۸�����
     *
     * @param plainText ԭ��
     * @param a         ��ʼλ��
     * @param b         ��ֹλ��
     * @param data      Ҫ�޸ĵ�����
     * @return �޸ĺ������
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
     * ��16����String��������ת��Ϊbyte[]
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
     * ��ȡjsonMessage��Ϣ������JsonObject����
     *
     * @param jsonMessage json��Ϣ
     * @return JsonObject����
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
