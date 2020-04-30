package qa.infosec.testng.netsign.upki;

import cn.com.infosec.netsign.agent.UpkiAgent;
import cn.com.infosec.netsign.agent.UpkiResult;
import cn.com.infosec.netsign.frame.util.PrivateKeyUtil;
import org.testng.Assert;
import org.testng.Reporter;
import org.testng.annotations.Test;
import qa.infosec.testng.netsign.dataprovider.NetSignDataProvider;
import qa.infosec.testng.netsign.dataprovider.util.*;
import qa.infosec.testng.netsign.init.NetSignServerInit;

import java.util.Map;

/**
 * @author zhaoyongzhi
 * @ClassName: TestMakeCUPFacePayWLEnvelope
 * @date 2020-03-02 18:21
 * @Description: 刷脸支付制作数字信封
 * <p>用例覆盖点：</p>
 * <p>1）制作刷脸支付数字信封,对称密钥类型为SM4/AES</p>
 * <p>2）制作刷脸支付数字信封,对称密钥类型为3DES/DES</p>
 * <p>3）pinCrypto为null,算法类型为SM4/AES</p>
 * <p>4）pinCrypto为null,算法类型为3DES/DES</p>
 * <p>5）pinCrypto密文篡改,对称密钥类型SM4/AES</p>
 * <p>6）pinCrypto密文篡改，对称密钥类型3DES/DES</p>
 * <p>7）iv为null,填充模式为/ECB</p>
 * <p>8）iv为null,填充模式为/CBC/CFB/OFB</p>
 * <p>9）iv 长度错误</p>
 * <p>10）iv 篡改</p>
 * <p>11）iv 解密pin密文所需IV与加密敏感数据所用IV不一致</p>
 * <p>12）pinModeAndPadding 与加密时使用的填充模式不匹配</p>
 * <p>13）pinModeAndPadding 传入为空</p>
 * <p>14）pinModeAndPadding 传入为null</p>
 * <p>15）pinModeAndPadding 传入错误值</p>
 * <p>16）pinModeAndPadding 内容错误</p>
 * <p>17）noPaddingSecret 无需补位的敏感数据，长度非算法分组长度整数倍，算法类型为DES/3DES</p>
 * <p>18）noPaddingSecret 无需补位的敏感数据，长度非算法分组长度整数倍，算法类型为AES/SM4</p>
 * <p>19）noPaddingSecret 传入为null</p>
 * <p>20）paddingSecret 长度非算法分组长度整数倍，算法类型为3DES/DES</p>
 * <p>21）paddingSecret 长度非算法分组长度整数倍，算法类型为AES/SM4</p>
 * <p>22）paddingSecret 传入为null</p>
 * <p>23）paddingSecret 长度非算法分组长度整数倍,填充模式为/CBC/NoPadding</p>
 * <p>24）modeAndPadding 加密填充模式为空</p>
 * <p>25）modeAndPadding 加密填充模式为null</p>
 * <p>26）encDN 正确DN，对称算法类型为DES/3DES</p>
 * <p>27）encDN 正确DN，对称算法类型为AES/SM4</p>
 * <p>28）encDN DN不存在</p>
 * <p>29）encDN DN为空</p>
 * <p>30）encDN DN为null</p>
 */
@Test(groups = "abcjew.makecupfacepaywlenvelope")
public class TestMakeCUPFacePayWLEnvelope {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;

    NetSignServerInit init = new NetSignServerInit();
    UpkiAgent agent;
    SFTPFile tmp = new SFTPFile();
    UtilsAgent2G utils;

    {
        Map<String, String> map = ParseFile.parseProperties(null);
        ip = map.get("ServerIP");
        port = map.get("ServerPortPBC2G");
        password = map.get("APIPassword");

        host = map.get("sftp_ip");
        sftp_port = map.get("sftp_port");
        sftp_user = map.get("sftp_user");
        sftp_password = map.get("sftp_password");

        agent = init.upkiStart(ip, port, password, true, 20);
        utils = init.utilsStart(ip, port, password);
        tmp.downFile(sftp_user, host, sftp_port, sftp_password, ParameterUtil.sftpsymmpath,
                ParameterUtil.localsymmpath);
        System.out.println("NetSignServerInit OK");
    }

    /**
     * 刷脸支付制作数字信封：对称算法使用SM4/AES
     *
     * @param modeAndPadding 填充模式
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_01(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("刷脸支付制作数字信封：对称算法使用SM4/AES，执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作刷脸支付数字信封：对称密钥类型为DES/3DES
     *
     * @param modeAndPadding 填充模式
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-8-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_02(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(8).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(8).getBytes();
        paddingSecret[1] = Utils.getRandomString(8).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100112) {
                    Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("制作刷脸支付数字信封(makeCUPFacePayWLEnvelope)：不支持DES");
            }
            System.out.println("刷脸支付制作数字信封：对称密钥类型为DES/3DES，执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作刷脸支付数字信封：pinCrypto为null,算法类型为SM4/AES
     *
     * @param modeAndPadding 填充模式
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "alg-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_03(String keyType, String modeAndPadding) {

        byte[] iv = Utils.getRandomString(16).getBytes();
        String pinModeAndPadding = keyType + modeAndPadding;
        String encDn = "O=infosec,CN=sm2_rev";

        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(null, null, null, null,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("刷脸支付制作数字信封：pinCrypto为null,算法类型为SM4/AES，执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作刷脸支付数字信封：pinCrypto为null,算法类型为3DES/DES
     *
     * @param modeAndPadding 填充模式
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "alg-8-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_04(String keyType, String modeAndPadding) {

        byte[] iv = Utils.getRandomString(8).getBytes();
        String pinModeAndPadding = keyType + modeAndPadding;
        String encDn = "O=infosec,CN=sm2_rev";

        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(8).getBytes();
        paddingSecret[1] = Utils.getRandomString(8).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(null, null, null, null,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100112) {
                    Assert.fail("制作刷脸支付数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("制作刷脸支付数字信封(makeCUPFacePayWLEnvelope)：不支持DES/RC2/RC4");
            }
            System.out.println("刷脸支付制作数字信封：pinCrypto为null,算法类型为SM4/AES，执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：pinCrypto密文篡改,对称密钥类型SM4/AES
     *
     * @param modeAndPadding 填充模式
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_05(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            //篡改pin密文
            pinCry_01[0] = Utils.modifyData(pinCry_01[0], 5, 10, "abcde");
            pinCry_02[0] = Utils.modifyData(pinCry_02[0], 5, 10, "abcde");
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("刷脸支付制作数字信封：pinCrypto密文篡改,对称密钥类型SM4/AES，执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：pinCrypto密文篡改，对称密钥类型3DES/DES
     *
     * @param modeAndPadding 填充模式
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-8-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_06(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(8).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            //篡改pin密文
            pinCry_01[0] = Utils.modifyData(pinCry_01[0], 5, 10, "abcde");
            pinCry_02[0] = Utils.modifyData(pinCry_02[0], 5, 10, "abcde");
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(8).getBytes();
        paddingSecret[1] = Utils.getRandomString(8).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100112) {
                    Assert.fail("制作刷脸支付数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("制作刷脸支付数字信封(makeCUPFacePayWLEnvelope)：不支持DES");
            }
            System.out.println("刷脸支付制作数字信封：pinCrypto密文篡改，对称密钥类型3DES/DES，执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：iv为null,填充模式为/ECB
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-0",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_07(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = null;
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/ECB/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100112) {
                    Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("制作刷脸支付数字信封(makeCUPFacePayWLEnvelope):填充模式为/ECB时，不支持DES");
            }
            System.out.println("刷脸支付制作数字信封：iv为null,填充模式为/ECB，执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：iv为null,填充模式为/CBC/CFB/OFB
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-0-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_08(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = null;
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -1022) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("刷脸支付制作数字信封：iv为null,填充模式为/CBC/CFB/OFB，执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：iv 长度错误
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-0-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_09(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(7).getBytes();
        byte[] iv2 = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv2, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv2, keyType, modeAndPadding);
//            if (utils.getReturnCode() != 1) {
//                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
//            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -100110 && upkiResult.getReturnCode() != -100010) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("刷脸支付制作数字信封：iv 长度错误，执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：iv篡改
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_10(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] iv2 = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv2,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -100110) {
                if (upkiResult.getReturnCode() != 0) {
                    Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("制作刷脸支付数字信封(makeCUPFacePayWLEnvelope):解密PIN密文所用IV篡改仍能解密成功");
            }
            System.out.println("刷脸支付制作数字信封：iv 长度错误，执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：iv 解密pin密文所需IV与加密敏感数据所用IV不一致
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_11(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] iv2 = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv2, encDn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("刷脸支付制作数字信封：iv 解密pin密文所需IV与加密敏感数据所用IV不一致用例,执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：pinModeAndPadding 与加密时使用的填充模式不匹配
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-8-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_12(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(8).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            String modePadding = "/ECB/NoPadding";
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100112) {
                    Assert.fail("制作刷脸支付数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("制作刷脸支付数字信封(makeCUPFacePayWLEnvelope):不支持对称算法DES");
            }
            System.out.println("刷脸支付制作数字信封：pinModeAndPadding 与加密时使用的填充模式不匹配用例,执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：pinModeAndPadding 传入为空
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_13(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, "", iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -100110) {
                Assert.fail("制作刷脸支付数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("刷脸支付制作数字信封：pinModeAndPadding 传入为空用例,执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：pinModeAndPadding 传入为null
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_14(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, null, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -100110) {
                Assert.fail("制作刷脸支付数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("刷脸支付制作数字信封：pinModeAndPadding 传入为null用例,执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：pinModeAndPadding 内容错误
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_15(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, "ABC", iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -100110) {
                Assert.fail("制作刷脸支付数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("刷脸支付制作数字信封：pinModeAndPadding 内容错误用例,执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：pinModeAndPadding 内容错误
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_16(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, "ABC", iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -100110) {
                Assert.fail("制作刷脸支付数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("刷脸支付制作数字信封：pinModeAndPadding 内容错误用例,执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：noPaddingSecret,无需补位的敏感数据，长度非算法分组长度整数倍
     *
     * @param keyLableAndTypeAndData 返回算法类型为3DES/DES
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-8",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_17(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(8).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(17).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(17).getBytes();
        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -100116) {
                if (upkiResult.getReturnCode() != -100112) {
                    Assert.fail("制作刷脸支付数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("制作刷脸支付数字信封(makeCUPFacePayWLEnvelope):对称加密算法不支持DES");
            }
            System.out.println("刷脸支付制作数字信封：noPaddingSecret,无需补位的敏感数据，长度非算法分组长度整数倍用例,执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：noPaddingSecret,无需补位的敏感数据，长度非算法分组长度整数倍
     *
     * @param keyLableAndTypeAndData 返回算法类型为AES/SM4
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_18(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(17).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(17).getBytes();
        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -100116) {
                Assert.fail("制作刷脸支付数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("刷脸支付制作数字信封：noPaddingSecret,无需补位的敏感数据，长度非算法分组长度整数倍用例,执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：noPaddingSecret 传入为null
     *
     * @param keyLableAndTypeAndData 返回算法类型为3DES/DES
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_19(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = null;

        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作刷脸支付数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("刷脸支付制作数字信封：noPaddingSecret 传入为null用例,执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：paddingSecret 长度非算法分组长度整数倍
     *
     * @param keyLableAndTypeAndData 返回算法类型为3DES/DES
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-8",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_20(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(8).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();

        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(4).getBytes();
        paddingSecret[1] = Utils.getRandomString(5).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100112) {
                    Assert.fail("制作刷脸支付数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("制作刷脸支付数字信封(makeCUPFacePayWLEnvelope):对称加密算法不支持DES");
            }
            System.out.println("刷脸支付制作数字信封：paddingSecret 长度非算法分组长度整数倍,执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：paddingSecret 长度非算法分组长度整数倍
     *
     * @param keyLableAndTypeAndData 返回算法类型为AES/SM4
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_21(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();

        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(4).getBytes();
        paddingSecret[1] = Utils.getRandomString(5).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作刷脸支付数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("刷脸支付制作数字信封：paddingSecret 长度非算法分组长度整数倍用例,执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：paddingSecret 传入为null，算法类型为AES/SM4
     *
     * @param keyLableAndTypeAndData 返回算法类型为AES/SM4
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_22(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();

        // 添加需要补位的敏感数据
        byte[][] paddingSecret = null;

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作刷脸支付数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("刷脸支付制作数字信封：paddingSecret 传入为null，算法类型为AES/SM4用例,执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：paddingSecret长度非算法分组长度整数倍,填充模式为/CBC/NoPadding
     *
     * @param keyLableAndTypeAndData 返回算法类型为AES/SM4
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_23(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/NoPadding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();

        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(6).getBytes();
        paddingSecret[1] = Utils.getRandomString(6).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100116) {
                    Assert.fail("制作刷脸支付数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("制作刷脸支付数字信封(makeCUPFacePayWLEnvelope):加密填充模式为/CBC/NoPadding时，需要补位的敏感数据长度也需要与算法分组长度一致");
            }
            System.out.println("刷脸支付制作数字信封：paddingSecret长度非算法分组长度整数倍,填充模式为/CBC/NoPadding用例,执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：modeAndPadding 加密填充模式为空
     *
     * @param keyLableAndTypeAndData 返回算法类型为AES/SM4
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_24(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/NoPadding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();

        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, "", iv, encDn);
            if (upkiResult.getReturnCode() != -1022) {
                Assert.fail("制作刷脸支付数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("刷脸支付制作数字信封：modeAndPadding 加密填充模式为空用例,执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：modeAndPadding 加密填充模式为null
     *
     * @param keyLableAndTypeAndData 返回算法类型为AES/SM4
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_25(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/NoPadding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();

        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, null, iv, encDn);
            if (upkiResult.getReturnCode() != -1022) {
                Assert.fail("制作刷脸支付数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("刷脸支付制作数字信封：modeAndPadding 加密填充模式为空用例,执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：encDN 正确DN
     *
     * @param keyLableAndTypeAndData 返回算法类型为DES/3DES
     * @param encDn                  加密dn
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "symmkey-8-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_26(String keyLableAndTypeAndData, String encDn) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(8).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();

        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100112) {
                    Assert.fail("制作刷脸支付数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("制作刷脸支付数字信封(makeCUPFacePayWLEnvelope)：不支持DES");
            }
            System.out.println("刷脸支付制作数字信封：encDN 正确DN用例,执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：encDN 正确DN
     *
     * @param keyLableAndTypeAndData 返回算法类型为AES/SM4
     * @param encDn                  加密dn
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "symmkey-16-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_27(String keyLableAndTypeAndData, String encDn) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();

        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作刷脸支付数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("刷脸支付制作数字信封：encDN 正确DN用例,执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：encDN,DN不存在
     *
     * @param keyLableAndTypeAndData 返回算法类型为AES/SM4
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_28(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "CN=123";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();

        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -100203) {
                Assert.fail("制作刷脸支付数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("刷脸支付制作数字信封：encDN,DN不存在用例,执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：encDN,DN为空
     *
     * @param keyLableAndTypeAndData 返回算法类型为AES/SM4
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_29(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "";

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();

        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -1022) {
                Assert.fail("制作刷脸支付数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("刷脸支付制作数字信封：encDN,DN为空用例,执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付制作数字信封：encDN,DN为null
     *
     * @param keyLableAndTypeAndData 返回算法类型为AES/SM4
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_30(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = null;

        // 获取对称密钥data，解密对称密钥
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // 使用对称密钥对pin加密，得到pin密文
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("对称密钥对pin加密失败：" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // 添加两段pin密文到pinCrypto[][]数组
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // 添加无需补位的敏感数据
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();

        // 添加需要补位的敏感数据
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -1022) {
                Assert.fail("制作刷脸支付数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("刷脸支付制作数字信封：encDN,DN为空用例,执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }
}
