package qa.infosec.testng.netsign.dataprovider.util;

import cn.com.infosec.netsign.agent.NetSignAgentUtil;
import cn.com.infosec.netsign.agent.newcommunitor.CommunitorManager;
import cn.com.infosec.netsign.agent.service.NSPSService;
import cn.com.infosec.netsign.base.NSMessage;
import cn.com.infosec.netsign.base.NSMessageOpt;
import cn.com.infosec.netsign.frame.util.PrivateKeyUtil;
import cn.com.infosec.netsign.pool.Poolable;
import cn.com.infosec.util.Base64;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Date;


/**
 * @author zhaoyongzhi
 * @ClassName: UtilsAgent2G
 * @date 2020-04-28 14:03
 * @Description:
 */
public class UtilsAgent2G implements Poolable {
    static boolean checkIPAddress = true;
    private Socket connection;
    private int timeout = 60000;
    private static Date now = null;
    private String ip;
    private int port;
    private byte[] pwd;
    protected CommunitorManager cm = null;
    protected int returnCode;
    public boolean isDebug = false;
    private static SimpleDateFormat format = null;
    protected String errMsg;

    public UtilsAgent2G() {
        this.cm = new CommunitorManager(true);
    }

    public UtilsAgent2G(boolean usingSingleServiceList) {
        this.cm = new CommunitorManager(usingSingleServiceList);
    }

    private boolean openConnection() {
        this.logString("openConnection{}");
        boolean connectionok = true;
        if (checkIPAddress) {
            try {
                InetSocketAddress ia = new InetSocketAddress(this.ip, this.port);
                this.connection = new Socket();
                this.connection.connect(ia, this.timeout);
                this.connection.setTcpNoDelay(true);
                this.connection.setSoTimeout(this.timeout);
                this.connection.setSoLinger(true, 0);
            } catch (Exception var11) {
                this.logException(var11);
                connectionok = false;
            } finally {
                try {
                    this.connection.close();
                } catch (Exception var10) {
                }

            }
        }

        NSPSService s = new NSPSService();
        s.setIp(this.ip);
        s.setPort(this.port);
        s.setTimeout(this.timeout);
        s.setApiPasswd(this.pwd);
        this.cm.addService(s);
        return connectionok;
    }

    public boolean openSignServer(String ip, int port, String password) {
        this.logString("openSignServer{ip:" + ip + ";port:" + port + "}");
        if (ip != null && !"".equals(ip) && port >= 0) {
            this.ip = ip;
            this.port = port;

            try {
                MessageDigest md = MessageDigest.getInstance("SHA1");
                this.pwd = md.digest(password.getBytes("GBK"));
            } catch (Exception var5) {
                this.logException(var5);
                return false;
            }

            return this.openConnection();
        } else {
            this.returnCode = -1025;
            return false;
        }
    }

    public boolean[] openSignServer(String ip, String port, String password) {
        this.logString("openSignServer{ip:" + ip + ";port:" + port + "}");
        if (ip != null && !"".equals(ip) && port != null && !"".equals(port)) {
            if (ip.indexOf(",") < 0) {
                boolean result = this.openSignServer(ip, Integer.parseInt(port), password);
                return new boolean[]{result};
            } else {
                String[] ips = ip.split(",");
                String[] ports = port.split(",");
                String[] passwords = password.split(",");
                boolean[] results = new boolean[ips.length];
                int i = 0;

                for (int length = ips.length; i < length; ++i) {
                    boolean result = this.openSignServer(ips[i], Integer.parseInt(ports[i]), passwords[i]);
                    results[i] = result;
                }

                return results;
            }
        } else {
            this.returnCode = -1025;
            return new boolean[]{false};
        }
    }

    protected NSMessageOpt sendMsg(NSMessage req) {
        try {
            return this.cm.sendMessageUsingLongConnection(req);
        } catch (Exception var3) {
            var3.printStackTrace(System.out);
        }
        return null;
    }

    public static boolean isEmpty(byte[] arr) {
        if (arr == null) {
            return true;
        } else {
            return arr.length == 0;
        }
    }

    public static boolean isEmpty(Object o) {
        if (o == null) {
            return true;
        } else {
            return o instanceof String && ((String) o).length() == 0;
        }
    }

    public void logString(String msg) {
        if (this.isDebug) {
            now.setTime(System.currentTimeMillis());
            String time = format.format(now);
            StringBuffer buf = new StringBuffer();
            buf.append("---------------NetSign(").append(time).append(")----------------\n");
            buf.append(msg).append("\n");
            buf.append("----------------------------------------------------------\n");
            System.out.print(buf.toString());
        }
    }

    public void logException(Throwable e) {
        if (this.isDebug) {
            now.setTime(System.currentTimeMillis());
            String time = format.format(now);
            System.out.println("---------------NetSign(" + time + ")----------------");
            System.out.println("An Exception catched:" + e.toString());
            System.out.println("Full stacktrace as below:");
            e.printStackTrace(System.out);
            System.out.flush();
            System.out.println("----------------------------------------------------------");
        }
    }

    @Override
    public boolean equals(Poolable poolable) {
        return false;
    }

    @Override
    public void init(Object o) {

    }

    @Override
    public void destory() {
        this.closeSignServer();
    }

    public boolean closeSignServer() {
        this.logString("closeSignServer{}");

        try {
            if (this.connection != null) {
                this.connection.close();
            }
        } catch (Exception var2) {
        }

        this.cm.closeCommunitor();
        return true;
    }

    public int getReturnCode() {
        return this.returnCode;
    }

    public String getErrorMsg() {
        return this.errMsg;
    }

    public byte[][] symmEncrypt(byte[] plainText, byte[] key, byte[] iv, String symmetricalAlg, String modAndPadding) {
        this.logString("symmEncrypt{plainText:" + plainText + "key:" + key + " iv: " + iv + " symmetricalAlg:" + symmetricalAlg + " modAndPadding:" + modAndPadding + "}");
        NSMessage req = NetSignAgentUtil.createMessage("SymmEncryptionWithModeProcessor");
        if (isEmpty(plainText)) {
            this.logString("Parameter error: plainText is null ");
            this.returnCode = -1026;
            return (byte[][]) null;
        } else if (isEmpty(key)) {
            this.logString("Parameter error: key is null ");
            this.returnCode = -1026;
            return (byte[][]) null;
        } else if (isEmpty((Object) symmetricalAlg)) {
            this.logString("Parameter error: symmetricalAlg is null ");
            this.returnCode = -1026;
            return (byte[][]) null;
        } else {
            req.setPlainText(plainText);
            req.setEncKey(key);
            req.setKeyHash(iv);
            req.setSymmetricalAlg(symmetricalAlg);
            req.setBankName(modAndPadding);
            req.setBankID("enc");
            NSMessage res = this.sendMsg(req);
            if (res != null) {
                this.returnCode = res.getResult();
                this.logString("symmEncrypt{returnCode:" + this.returnCode + "}");
                if (this.returnCode >= 0) {
                    byte[][] result = new byte[][]{res.getCryptoText(), res.getKeyHash()};
                    return result;
                } else {
                    this.errMsg = res.getErrMsg();
                    return (byte[][]) null;
                }
            } else {
                this.returnCode = -1004;
                this.logString("symmEncrypt{connect to server failed}");
                return (byte[][]) null;
            }
        }
    }
    public byte[] symmDecrypt(byte[] cryptoText, byte[] key, byte[] iv, String symmetricalAlg, String modAndPadding) {
        this.logString("symmDecrypt{ key:" + key + " iv: " + iv + " symmetricalAlg:" + symmetricalAlg + " modAndPadding:" + modAndPadding + "}");
        NSMessage req = NetSignAgentUtil.createMessage("SymmEncryptionWithModeProcessor");
        if (isEmpty(key)) {
            this.logString("Parameter error: key is null ");
            this.returnCode = -1026;
            return null;
        } else if (isEmpty(cryptoText)) {
            this.logString("Parameter error: cryptoText is null ");
            this.returnCode = -1026;
            return null;
        } else if (isEmpty((Object)symmetricalAlg)) {
            this.logString("Parameter error: symmetricalAlg is null ");
            this.returnCode = -1026;
            return null;
        } else {
            req.setEncKey(key);
            req.setKeyHash(iv);
            req.setCryptoText(cryptoText);
            req.setSymmetricalAlg(symmetricalAlg);
            req.setBankName(modAndPadding);
            req.setBankID("dec");
            NSMessage res = this.sendMsg(req);
            if (res != null) {
                this.returnCode = res.getResult();
                this.logString("symmDecrypt{returnCode:" + this.returnCode + "}");
                if (this.returnCode >= 0) {
                    return res.getPlainText();
                } else {
                    this.errMsg = res.getErrMsg();
                    return null;
                }
            } else {
                this.returnCode = -1004;
                this.logString("symmDecrypt{connect to server failed}");
                return null;
            }
        }
    }

    public static void main(String[] args) {
        UtilsAgent2G utils = new UtilsAgent2G();
        utils.openSignServer("10.20.83.150", 20002, "");
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        String keyData = "f+GmcaSm9PiL5OF4jvfkBg==";
        String keyType = "SM4";
        String keyLable = "goldExchMasterKey_SM4";
        String password = keyLable + keyType;
        byte[] privateKey = null;
        byte[] iv = Utils.getRandomString(16).getBytes();
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);

            byte[][] bytes = utils.symmEncrypt(pinText_01, privateKey, iv, "SM4", "/OFB/PKCS7Padding");
            String encode = Base64.encode(bytes[0]);
            System.out.println(encode);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
