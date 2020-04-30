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

import java.io.IOException;
import java.util.Map;

/**
 * @author zhaoyongzhi
 * @ClassName: TestDecryptCUPFacePayWLEnvelope
 * @date 2020-04-30 14:21
 * @Description: 刷脸支付解密数字信封
 * <p>用例覆盖点：</p>
 * <p>1）刷脸支付解密数字信封：对称密钥类型为SM4/AES</p>
 * <p>2）刷脸支付解密数字信封：对称密钥类型为3DES/DES</p>
 * <p>3）刷脸支付解密数字信封：crypto 解密密文为空</p>
 * <p>4）刷脸支付解密数字信封：crypto密文篡改</p>
 * <p>5）刷脸支付解密数字信封：encPinKeyLabel 解密密钥号为null</p>
 * <p>6）刷脸支付解密数字信封：encPinKeyLabel 解密密钥号为空</p>
 * <p>7）刷脸支付解密数字信封：encPinKeyLabel 解密密钥号不存在</p>
 * <p>8）刷脸支付解密数字信封：pinModeAndPadding 解密pin需要的填充模式为null</p>
 * <p>9）刷脸支付解密数字信封：pinModeAndPadding 解密pin需要的填充模式为空</p>
 * <p>10）刷脸支付解密数字信封：pinModeAndPadding 解密pin需要的填充模式内容错误</p>
 * <p>11）刷脸支付解密数字信封：pinIv 解密pinIv与加密时不一致</p>
 * <p>12）刷脸支付解密数字信封：pinIv 解密pinIv为null</p>
 * <p>13）刷脸支付解密数字信封：modeAndPadding 解密敏感数据的填充模式，为空</p>
 * <p>14）刷脸支付解密数字信封：modeAndPadding 解密敏感数据的填充模式，为null</p>
 * <p>15）刷脸支付解密数字信封：modeAndPadding 解密敏感数据的填充模式，内容错误</p>
 * <p>16）刷脸支付解密数字信封：iv 解密敏感数据所需向量，传入为null</p>
 * <p>17）刷脸支付解密数字信封：iv 解密敏感数据所需向量，篡改</p>
 * <p>18）刷脸支付解密数字信封：decDN 正确DN,对称密钥SM4/AES</p>
 * <p>19）刷脸支付解密数字信封：decDN 正确DN,对称密钥3DES/DES</p>
 * <p>20）刷脸支付解密数字信封：decDN 为空</p>
 * <p>21）刷脸支付解密数字信封：decDN 为null</p>
 * <p>22）刷脸支付解密数字信封：decDN 不存在</p>
 */
@Test(groups = "abcjew.decryptcupfacepaywlenvelope")
public class TestDecryptCUPFacePayWLEnvelope {
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
     * 刷脸支付解密数字信封：对称密钥类型为SM4/AES
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_01(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
        // 解密数字信封
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != 0) {
                    Assert.fail("刷脸支付解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("刷脸支付解密数字信封：对称密钥类型为SM4/AES用例，执行成功");
            } catch (Exception e) {
                Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
            }
        }
    }

    /**
     * 刷脸支付解密数字信封：对称密钥类型为DES/3DES
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-8-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_02(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100112) {
                    Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
        // 解密数字信封
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != 0) {
                    Assert.fail("刷脸支付解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("刷脸支付解密数字信封：对称密钥类型为3DES/DES用例，执行成功");
            } catch (Exception e) {
                Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
            }
        }
    }

    /**
     * 刷脸支付解密数字信封：crypto 解密密文为空
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal")
    public void testDecryptCUPFacePayWLEnvelope_03() {
        String keyLable = "ccfccbMasterKey_SM4";
        byte[] iv = Utils.getRandomString(16).getBytes();
        String pinModeAndPadding = "SM4/CBC/NoPadding";
        String encDn = "O=infosec,CN=sm2_rev";
        // 解密数字信封
        try {
            UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(null, keyLable, pinModeAndPadding, iv,
                    pinModeAndPadding, iv, encDn);
            if (upkiResult1.getReturnCode() != -1022) {
                Assert.fail("刷脸支付解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
            System.out.println("刷脸支付解密数字信封：crypto 解密密文为空用例，执行成功");
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 刷脸支付解密数字信封：crypto密文篡改
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_04(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
        // 解密数字信封
        if (crypto != null) {
            try {
                for (int i = 0; i < crypto.length; i++) {
                    for (int j = 0; j < crypto[0].length; j++) {
                        crypto[i][j] = Utils.modifyData(crypto[i][j], 2, 5, "abc");
                    }
                }
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != -100004) {
                    Assert.fail("刷脸支付解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("刷脸支付解密数字信封：crypto密文篡改用例，执行成功");
            } catch (Exception e) {
                Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
            }
        }
    }

    /**
     * 刷脸支付解密数字信封：encPinKeyLabel 解密密钥号为null
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_05(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
        // 解密数字信封
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, null, pinModeAndPadding, iv,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != -1022) {
                    Assert.fail("刷脸支付解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("刷脸支付解密数字信封：encPinKeyLabel 解密密钥号为null用例，执行成功");
            } catch (Exception e) {
                Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
            }
        }
    }

    /**
     * 刷脸支付解密数字信封：encPinKeyLabel 解密密钥号为空
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_06(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
        // 解密数字信封
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, "", pinModeAndPadding, iv,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != -1022) {
                    Assert.fail("刷脸支付解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("刷脸支付解密数字信封：encPinKeyLabel 解密密钥号为空用例，执行成功");
            } catch (Exception e) {
                Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
            }
        }
    }

    /**
     * 刷脸支付解密数字信封：encPinKeyLabel 解密密钥号不存在
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_07(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
        // 解密数字信封
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, "CN=123", pinModeAndPadding, iv,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != -100004) {
                    Assert.fail("刷脸支付解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("刷脸支付解密数字信封：encPinKeyLabel 解密密钥号不存在用例，执行成功");
            } catch (Exception e) {
                Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
            }
        }
    }

    /**
     * 刷脸支付解密数字信封：pinModeAndPadding 解密pin需要的填充模式为null
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_08(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
        // 解密数字信封
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, null, iv,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != -100116) {
                    Assert.fail("刷脸支付解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("刷脸支付解密数字信封：pinModeAndPadding 解密pin需要的填充模式为null用例，执行成功");
            } catch (Exception e) {
                Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
            }
        }
    }

    /**
     * 刷脸支付解密数字信封：pinModeAndPadding 解密pin需要的填充模式为空
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_09(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
        // 解密数字信封
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, "", iv,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != -100116) {
                    Assert.fail("刷脸支付解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("刷脸支付解密数字信封：pinModeAndPadding 解密pin需要的填充模式为空用例，执行成功");
            } catch (Exception e) {
                Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
            }
        }
    }

    /**
     * 刷脸支付解密数字信封：pinModeAndPadding 解密pin需要的填充模式内容错误
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_10(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
        // 解密数字信封
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, "abc", iv,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != -100116) {
                    Assert.fail("刷脸支付解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("刷脸支付解密数字信封：pinModeAndPadding 解密pin需要的填充模式内容错误，执行成功");
            } catch (Exception e) {
                Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
            }
        }
    }

    /**
     * 刷脸支付解密数字信封：pinIv 解密pinIv与加密时不一致
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_11(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
        // 解密数字信封
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv2,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != 0) {
                    Assert.fail("刷脸支付解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("刷脸支付解密数字信封：pinModeAndPadding 解密pin需要的填充模式内容错误，执行成功");
            } catch (Exception e) {
                Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
            }
        }
    }

    /**
     * 刷脸支付解密数字信封：pinIv 解密pinIv为null
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_12(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
        // 解密数字信封
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, null,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != -1022) {
                    Assert.fail("刷脸支付解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("刷脸支付解密数字信封：pinIv 解密pinIv为null用例，执行成功");
            } catch (Exception e) {
                Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
            }
        }
    }

    /**
     * 刷脸支付解密数字信封：modeAndPadding 解密敏感数据的填充模式，为空
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_13(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
        // 解密数字信封
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, null,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != -1022) {
                    Assert.fail("刷脸支付解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("刷脸支付解密数字信封：pinIv 解密pinIv为null用例，执行成功");
            } catch (Exception e) {
                Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
            }
        }
    }

    /**
     * 刷脸支付解密数字信封：modeAndPadding 解密敏感数据的填充模式，为null
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_14(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
        // 解密数字信封
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        null, iv, encDn);
                if (upkiResult1.getReturnCode() != -1022) {
                    Assert.fail("刷脸支付解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("刷脸支付解密数字信封：pinIv 解密pinIv为null用例，执行成功");
            } catch (Exception e) {
                Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
            }
        }
    }

    /**
     * 刷脸支付解密数字信封：modeAndPadding 解密敏感数据的填充模式，内容错误
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_15(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
        // 解密数字信封
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        "123asd", iv, encDn);
                if (upkiResult1.getReturnCode() != -100004) {
                    Assert.fail("刷脸支付解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("刷脸支付解密数字信封：modeAndPadding 解密敏感数据的填充模式，内容错误用例，执行成功");
            } catch (Exception e) {
                Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
            }
        }
    }

    /**
     * 刷脸支付解密数字信封：iv 解密敏感数据所需向量，传入为null
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_16(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
        // 解密数字信封
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        pinModeAndPadding, null, encDn);
                if (upkiResult1.getReturnCode() != -1022) {
                    Assert.fail("刷脸支付解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("刷脸支付解密数字信封：iv 解密敏感数据所需向量，传入为null用例，执行成功");
            } catch (Exception e) {
                Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
            }
        }
    }

    /**
     * 刷脸支付解密数字信封：iv 解密敏感数据所需向量，篡改
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_17(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
        // 解密数字信封
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        pinModeAndPadding, iv2, encDn);
                if (upkiResult1.getReturnCode() != -100123) {
                    if (upkiResult1.getReturnCode() != 0) {
                        Assert.fail("刷脸支付解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                    }
                    Reporter.log("刷脸支付解密数字信封：iv 解密敏感数据所需向量，篡改,可以执行成功，但解密得到内容错误");
                }
                System.out.println("刷脸支付解密数字信封：iv 解密敏感数据所需向量，篡改用例，执行成功");
            } catch (Exception e) {
                Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
            }
        }
    }

    /**
     * 刷脸支付解密数字信封：decDN 正确DN
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "symmkey-16-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_18(String keyLableAndTypeAndData, String encDn) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
        // 解密数字信封
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != 0) {
                    Assert.fail("刷脸支付解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("刷脸支付解密数字信封：decDN 正确DN用例，执行成功");
            } catch (Exception e) {
                Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
            }
        }
    }

    /**
     * 刷脸支付解密数字信封：decDN 正确DN
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "symmkey-8-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_19(String keyLableAndTypeAndData, String encDn) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100112) {
                    Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                return;
            }
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
        // 解密数字信封
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != 0) {
                    Assert.fail("刷脸支付解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("刷脸支付解密数字信封：decDN 正确DN用例，执行成功");
            } catch (Exception e) {
                Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
            }
        }
    }

    /**
     * 刷脸支付解密数字信封：decDN 为空
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "symmkey-16-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_20(String keyLableAndTypeAndData, String encDn) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
        // 解密数字信封
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        pinModeAndPadding, iv, "");
                if (upkiResult1.getReturnCode() != -1022) {
                    Assert.fail("刷脸支付解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("刷脸支付解密数字信封：decDN 为空，执行成功");
            } catch (Exception e) {
                Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
            }
        }
    }

    /**
     * 刷脸支付解密数字信封：decDN 不存在
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "symmkey-16-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_22(String keyLableAndTypeAndData, String encDn) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
        // 解密数字信封
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        pinModeAndPadding, iv, null);
                if (upkiResult1.getReturnCode() != -1022) {
                    Assert.fail("刷脸支付解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("刷脸支付解密数字信封：decDN 为null，执行成功");
            } catch (Exception e) {
                Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
            }
        }
    }

    /**
     * 刷脸支付解密数字信封：decDN 为null
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "symmkey-16-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_21(String keyLableAndTypeAndData, String encDn) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("刷脸支付制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
        }
        // 解密数字信封
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        pinModeAndPadding, iv, null);
                if (upkiResult1.getReturnCode() != -1022) {
                    Assert.fail("刷脸支付解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("刷脸支付解密数字信封：decDN 不存在，执行成功");
            } catch (Exception e) {
                Assert.fail("刷脸支付制作数字信封失败：" + e.getMessage());
            }
        }
    }

}
