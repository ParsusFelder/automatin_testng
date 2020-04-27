package qa.infosec.testng.netsign.upki;

import cn.com.infosec.netsign.agent.UpkiAgent;
import cn.com.infosec.netsign.agent.UpkiResult;
import cn.com.infosec.netsign.json.JsonObject;
import cn.com.infosec.netsign.json.JsonValueString;
import org.testng.Assert;
import org.testng.Reporter;
import org.testng.annotations.Test;
import qa.infosec.testng.netsign.dataprovider.NetSignDataProvider;
import qa.infosec.testng.netsign.dataprovider.util.*;
import qa.infosec.testng.netsign.init.NetSignServerInit;

import java.util.Map;
import java.util.Random;

import static qa.infosec.testng.netsign.dataprovider.util.JsonMessage.*;

/**
 * @author zhaoyongzhi
 * @ClassName: TestCUPCQPEncryptAndSign
 * @date 2020-04-26 18:17
 * @Description: 云闪付加密并签名
 * <p>用例覆盖点：</p>
 * <p>1）云闪付加密并签名：使用正常状态证书DN进行加密并签名</p>
 * <p>2）云闪付加密并签名：使用正常状态证书SN进行加密并签名</p>
 * <p>3）云闪付加密并签名：使用正常状态证书Bankcode进行加密并签名</p>
 * <p>4）云闪付加密并签名：处于黑名单的证书Bankcode进行加密并签名</p>
 * <p>5）云闪付加密并签名：appId有键有值，值含中英文大小写特殊字符</p>
 * <p>6）云闪付加密并签名：appId有键无值</p>
 * <p>7）云闪付加密并签名：appId无键无值</p>
 * <p>8）云闪付加密并签名：indUsrId有键有值，值含中英文大小写特殊字符</p>
 * <p>9）云闪付加密并签名：indUsrId有键无值</p>
 * <p>10）云闪付加密并签名：indUsrId无键无值</p>
 * <p>11）云闪付加密并签名：nonceStr有键有值，值含中英文大小写特殊字符</p>
 * <p>12）云闪付加密并签名：nonceStr有键无值</p>
 * <p>13）云闪付加密并签名：nonceStr无键无值</p>
 * <p>14）云闪付加密并签名：timestamp有键有值，值含中英文大小写特殊字符</p>
 * <p>15）云闪付加密并签名：timestamp有键无值</p>
 * <p>16）云闪付加密并签名：timestamp无键无值</p>
 * <p>17）云闪付加密并签名：chnl有键有值，值含中英文大小写特殊字符</p>
 * <p>18）云闪付加密并签名：chnl有键无值</p>
 * <p>19）云闪付加密并签名：chnl无键无值</p>
 * <p>20）云闪付加密并签名：cardNo有键有值，值含中英文大小写特殊字符</p>
 * <p>21）云闪付加密并签名：cardNo有键无值</p>
 * <p>22）云闪付加密并签名：cardNo无键无值</p>
 * <p>23）云闪付加密并签名：mobile有键有值，值含中英文大小写特殊字符</p>
 * <p>24）云闪付加密并签名：mobile有键无值</p>
 * <p>25）云闪付加密并签名：mobile无键无值</p>
 * <p>26）云闪付加密并签名：realNm有键有值，值含中英文大小写特殊字符</p>
 * <p>27）云闪付加密并签名：realNm有键无值</p>
 * <p>28）云闪付加密并签名：realNm无键无值</p>
 * <p>29）云闪付加密并签名：certifId有键有值，值含中英文大小写特殊字符</p>
 * <p>30）云闪付加密并签名：certifId有键无值</p>
 * <p>31）云闪付加密并签名：certifId无键无值</p>
 * <p>32）云闪付加密并签名：accType有键有值，值含中英文大小写特殊字符</p>
 * <p>33）云闪付加密并签名：accType有键无值</p>
 * <p>34）云闪付加密并签名：accType无键无值</p>
 * <p>35）云闪付加密并签名：certType有键有值，值含中英文大小写特殊字符</p>
 * <p>36）云闪付加密并签名：certType有键无值</p>
 * <p>37）云闪付加密并签名：certType无键无值</p>
 * <p>38）云闪付加密并签名：加密证书DN为空或null</p>
 * <p>39）云闪付加密并签名：签名证书DN为空或null</p>
 * <p>40）云闪付加密并签名：加密证书DN不存在</p>
 * <p>41）云闪付加密并签名：签名证书DN不存在</p>
 */
@Test(groups = "abcjew.cupcqpencryptandsign")
public class TestCUPCQPEncryptAndSign {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;
    Random random = new Random();

    NetSignServerInit init = new NetSignServerInit();
    UpkiAgent agent;
    SFTPFile tmp = new SFTPFile();
    JsonValueString jsonValue = new JsonValueString();

    {
        // 解析netsignconfig.properties配置文件，获取所需信息,confpath=null 使用默认路径
        Map<String, String> map = ParseFile.parseProperties(null);
        ip = map.get("ServerIP");
        port = map.get("ServerPortPBC2G");
        password = map.get("APIPassword");
        host = map.get("sftp_ip");
        sftp_port = map.get("sftp_port");
        sftp_user = map.get("sftp_user");
        sftp_password = map.get("sftp_password");

        agent = init.upkiStart(ip, port, password, true, 20);
//        tmp.downFile(sftp_user, host, sftp_port, sftp_password, ParameterUtil.sftpkeystorepath,
//                ParameterUtil.keystorepath);
        System.out.println("NetSignServerInit OK");
    }

    /**
     * 云闪付加密并签名：使用正常状态证书DN进行加密并签名
     *
     * @param dn 正常状态证书DN
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal", dataProvider = "all-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPCQPEncryptAndSign_01(String dn) {
        System.out.println("云闪付加密并签名：使用正常状态证书DN进行加密并签名");

        String jsonMessage = CUPCQPEncAndsignMessage;
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonMessage, dn, dn);
            if (!upkiResult.getBoolResult() || upkiResult.getReturnCode() != 0) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：使用正常状态证书SN进行加密并签名
     *
     * @param sn 正常状态证书SN
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal", dataProvider = "all-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPCQPEncryptAndSign_02(String sn) {
        System.out.println("云闪付加密并签名：使用正常状态证书DN进行加密并签名");

        String jsonMessage = CUPCQPEncAndsignMessage;
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonMessage, sn, sn);
            if (!upkiResult.getBoolResult() || upkiResult.getReturnCode() != 0) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：使用正常状态证书Bankcode进行加密并签名
     *
     * @param bankcode 正常状态证书Bankcode
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal", dataProvider = "all-bankcode", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPCQPEncryptAndSign_03(String bankcode) {
        System.out.println("云闪付加密并签名：使用正常状态证书Bankcode进行加密并签名");

        String jsonMessage = CUPCQPEncAndsignMessage;
        if ("10year".equals(bankcode)) {
            return;
        }
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonMessage, bankcode, bankcode);
            if (!upkiResult.getBoolResult() || upkiResult.getReturnCode() != 0) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：处于黑名单的证书Bankcode进行加密并签名
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_04() {
        System.out.println("云闪付加密并签名：处于黑名单的证书Bankcode进行加密并签名");

        String jsonMessage = CUPCQPEncAndsignMessage;
        String bankcode = "10year";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonMessage, bankcode, bankcode);
            if (upkiResult.getReturnCode() != -100203) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：appId有键有值，值含中英文大小写特殊字符
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_05() {
        System.out.println("云闪付加密并签名：appId有键有值，值含中英文大小写特殊字符");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("中英文abcABC!@#");
        jsonObject.put("appId", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：appId有键无值
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_06() {
        System.out.println("云闪付加密并签名：appId有键无值");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("");
        jsonObject.put("appId", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：appId无键无值
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_07() {
        System.out.println("云闪付加密并签名：appId无键无值");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonObject.remove("appId");
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：indUsrId有键有值，值含中英文大小写特殊字符
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_08() {
        System.out.println("云闪付加密并签名：indUsrId有键有值，值含中英文大小写特殊字符");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("中英文abcABC!@#");
        jsonObject.put("indUsrId", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：indUsrId有键无值
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_09() {
        System.out.println("云闪付加密并签名：indUsrId有键无值");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("");
        jsonObject.put("indUsrId", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：indUsrId无键无值
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_10() {
        System.out.println("云闪付加密并签名：indUsrId无键无值");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonObject.remove("indUsrId");
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：nonceStr有键有值，值含中英文大小写特殊字符
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_11() {
        System.out.println("云闪付加密并签名：nonceStr有键有值，值含中英文大小写特殊字符");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("中英文abcABC!@#");
        jsonObject.put("nonceStr", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：nonceStr有键无值
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_12() {
        System.out.println("云闪付加密并签名：nonceStr有键无值");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("");
        jsonObject.put("nonceStr", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：nonceStr无键无值
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_13() {
        System.out.println("云闪付加密并签名：nonceStr无键无值");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonObject.remove("nonceStr");
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：timestamp有键有值，值含中英文大小写特殊字符
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_14() {
        System.out.println("云闪付加密并签名：timestamp有键有值，值含中英文大小写特殊字符");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("中英文abcABC!@#");
        jsonObject.put("timestamp", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：timestamp有键无值
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_15() {
        System.out.println("云闪付加密并签名：timestamp有键无值");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("");
        jsonObject.put("timestamp", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：timestamp无键无值
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_16() {
        System.out.println("云闪付加密并签名：timestamp无键无值");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonObject.remove("timestamp");
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：chnl有键有值，值含中英文大小写特殊字符
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_17() {
        System.out.println("云闪付加密并签名：chnl有键有值，值含中英文大小写特殊字符");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("中英文abcABC!@#");
        jsonObject.put("chnl", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：chnl有键无值
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_18() {
        System.out.println("云闪付加密并签名：chnl有键无值");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("");
        jsonObject.put("chnl", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：chnl无键无值
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_19() {
        System.out.println("云闪付加密并签名：chnl无键无值");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonObject.remove("chnl");
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：cardNo有键有值，值含中英文大小写特殊字符
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_20() {
        System.out.println("云闪付加密并签名：cardNo有键有值，值含中英文大小写特殊字符");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("中英文abcABC!@#");
        jsonObject.put("cardNo", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：cardNo有键无值
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_21() {
        System.out.println("云闪付加密并签名：cardNo有键无值");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("");
        jsonObject.put("cardNo", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：cardNo无键无值
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_22() {
        System.out.println("云闪付加密并签名：cardNo无键无值");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonObject.remove("cardNo");
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：mobile有键有值，值含中英文大小写特殊字符
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_23() {
        System.out.println("云闪付加密并签名：mobile有键有值，值含中英文大小写特殊字符");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("中英文abcABC!@#");
        jsonObject.put("mobile", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：mobile有键无值
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_24() {
        System.out.println("云闪付加密并签名：mobile有键无值");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("");
        jsonObject.put("mobile", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：mobile无键无值
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_25() {
        System.out.println("云闪付加密并签名：mobile无键无值");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonObject.remove("mobile");
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：realNm有键有值，值含中英文大小写特殊字符
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_26() {
        System.out.println("云闪付加密并签名：realNm有键有值，值含中英文大小写特殊字符");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("中英文abcABC!@#");
        jsonObject.put("realNm", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：realNm有键无值
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_27() {
        System.out.println("云闪付加密并签名：realNm有键无值");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("");
        jsonObject.put("realNm", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：realNm无键无值
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_28() {
        System.out.println("云闪付加密并签名：realNm无键无值");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonObject.remove("realNm");
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：certifId有键有值，值含中英文大小写特殊字符
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_29() {
        System.out.println("云闪付加密并签名：certifId有键有值，值含中英文大小写特殊字符");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("中英文abcABC!@#");
        jsonObject.put("certifId", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：certifId有键无值
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_30() {
        System.out.println("云闪付加密并签名：certifId有键无值");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("");
        jsonObject.put("certifId", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：certifId无键无值
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_31() {
        System.out.println("云闪付加密并签名：certifId无键无值");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonObject.remove("certifId");
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：accType有键有值，值含中英文大小写特殊字符
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_32() {
        System.out.println("云闪付加密并签名：accType有键有值，值含中英文大小写特殊字符");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("中英文abcABC!@#");
        jsonObject.put("accType", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：accType有键无值
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_33() {
        System.out.println("云闪付加密并签名：accType有键无值");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("");
        jsonObject.put("accType", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：accType无键无值
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_34() {
        System.out.println("云闪付加密并签名：accType无键无值");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonObject.remove("accType");
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：certType有键有值，值含中英文大小写特殊字符
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_35() {
        System.out.println("云闪付加密并签名：certType有键有值，值含中英文大小写特殊字符");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("中英文abcABC!@#");
        jsonObject.put("certType", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：certType有键无值
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_36() {
        System.out.println("云闪付加密并签名：certType有键无值");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("");
        jsonObject.put("certType", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：certType无键无值
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_37() {
        System.out.println("云闪付加密并签名：certType无键无值");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonObject.remove("certType");
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：加密证书DN为空或null
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPCQPEncryptAndSign_38(String encDn) {
        System.out.println("云闪付加密并签名：加密证书DN为空或null");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), encDn, dn);
            if (upkiResult.getReturnCode() != -1026) {
                if (upkiResult.getReturnCode() != 0) {
                    Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("云闪付加密并签名(CUPCQPEncryptAndSign)：加密证书DN传入null可以执行成功");
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：签名证书DN为空或null
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPCQPEncryptAndSign_39(String signDn) {
        System.out.println("云闪付加密并签名：签名证书DN为空或null");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, signDn);
            if (upkiResult.getReturnCode() != -1026) {
                if (upkiResult.getReturnCode() != 0) {
                    Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("云闪付加密并签名(CUPCQPEncryptAndSign)：签名证书DN传入空或null可以执行成功");
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：加密证书DN不存在
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_40() {
        System.out.println("云闪付加密并签名：加密证书DN不存在");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String dn1 = "CN=123";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn1, dn);
            if (upkiResult.getReturnCode() != -100203) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }

    /**
     * 云闪付加密并签名：签名证书DN不存在
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_41() {
        System.out.println("云闪付加密并签名：签名证书DN不存在");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String dn1 = "CN=123";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn1);
            if (upkiResult.getReturnCode() != -100204) {
                Assert.fail("云闪付加密并签名失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("云闪付加密并签名失败：" + e.getMessage());
        }
    }
}
