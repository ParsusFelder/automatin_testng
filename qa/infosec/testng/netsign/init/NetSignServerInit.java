package qa.infosec.testng.netsign.init;

import cn.com.infosec.asn1.x509.X509NameTokenizer;
import cn.com.infosec.netsign.agent.PBCAgent2G;
import cn.com.infosec.netsign.agent.UpkiAgent;
import com.alibaba.fastjson.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

/**
 * Created by maxf on 18-05-14.
 * 初始化服务器连接
 */
public class NetSignServerInit {

    private static final String[] dNObjectsForward = {
            "1.2.840.113549.1.9.8", "1.2.840.113549.1.9.2", "emailaddress", "e", "email", "uid", "cn", "sn",
            "serialnumber", "gn", "givenname",
            "initials", "surname", "t", "ou", "o", "l", "st", "dc", "c"
    };
    private static final String[] dNObjects = dNObjectsForward;

    public NetSignServerInit() {

    }

    public PBCAgent2G start(String ip, String port, String password, boolean isUseConnectionPool, int maxPoolSize) {

        PBCAgent2G agent = null;

        try {
            System.out.println("NetSignServer Init!");
            agent = new PBCAgent2G();
            agent.openSignServer(ip, port, password);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return agent;
    }

    public UpkiAgent upkiStart(String ip, String port, String password, boolean isUseConnectionPool, int maxPoolSize) {

        UpkiAgent agent = null;

        try {
            System.out.println("NetSignServer Init!");
            agent = new UpkiAgent();
            agent.openSignServer(ip, port, password, isUseConnectionPool, maxPoolSize);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return agent;
    }

    public static String getDN(int order, String dn) {
        if ((dn == null) || dn.equals("")) {
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
                if (dn.startsWith("CN=") || dn.startsWith("cn="))
                    return turnDNString(dn);
                else
                    return dn;
            default:
                break;
        }
        return dn;
    }

    public static String setReverseDN(String dn) {
        if (dn.startsWith("CN=") || dn.startsWith("cn="))
            return turnDNString(dn);
        else
            return reverseDN(dn);
    }

    private static String turnDNString(String dn) {
        if (dn.indexOf(",") < 0)
            return dn;
        else {
            String split = (dn.indexOf(", ") > -1) ? ", " : ",";
            String[] pieces = dn.split(split);
            String tmp = "";
            for (int i = pieces.length - 1; i >= 0; i--) {
                tmp += pieces[i];
                if (i != 0)
                    tmp += split;
            }
            return tmp;
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
            StringBuffer buf = new StringBuffer();
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
                    if (!escaped) {
                        buf.append(c);
                        quoted = !quoted;
                    } else {
                        buf.append(c);
                    }
                    escaped = false;
                } else {
                    if (escaped || quoted) {
                        buf.append(c);
                        escaped = false;
                    } else if (c == '\\') {
                        buf.append(c);
                        escaped = true;
                    } else if ((c == ',') && (!escaped)) {
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
        //1. 定义一个字符串（A-Z，a-z，0-9）即62个数字字母；
        String str = "1234567890";
        //2. 由Random生成随机数
        Random random = new Random();
        StringBuffer sb = new StringBuffer();
        //3. 长度为几就循环几次
        for (int i = 0; i < length; ++i) {
            //从62个的数字或字母中选择
            int number = random.nextInt(10);
            //将产生的数字通过length次承载到sb中
            sb.append(str.charAt(number));
        }
        //将承载的字符转换成字符串
        return sb.toString();
    }


    public static String jsonsort(JSONObject json) {
        StringBuilder builder = new StringBuilder();
        List<String> list1 = new ArrayList<String>();
        list1.addAll(json.keySet());
        Collections.sort(list1);
        for (int i = 0; i < list1.size(); i++) {
            char ch = ' ';
            if (i < list1.size() - 1) {
                ch = '&';
            }
            builder.append(list1.get(i) + "=" + json.get(list1.get(i)).toString() + ch);
        }

        return builder.toString().trim() + '&';
    }


}
