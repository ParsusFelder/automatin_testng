package qa.infosec.testng.netsign.upki;

import cn.com.infosec.netsign.agent.UpkiAgent;
import cn.com.infosec.netsign.agent.UpkiResult;
import org.testng.Assert;
import org.testng.Reporter;
import org.testng.annotations.Test;
import qa.infosec.testng.netsign.dataprovider.NetSignDataProvider;
import qa.infosec.testng.netsign.dataprovider.util.ParameterUtil;
import qa.infosec.testng.netsign.dataprovider.util.ParseFile;
import qa.infosec.testng.netsign.dataprovider.util.SFTPFile;
import qa.infosec.testng.netsign.dataprovider.util.Utils;
import qa.infosec.testng.netsign.init.NetSignServerInit;

import java.util.Map;

/**
 * @author zhaoyongzhi
 * @ClassName: TestEncryptWangLianEnvelope
 * @date 2020-03-02 18:06
 * @Description: 制作网联格式数字信封
 * <p>用例覆盖点：</p>
 * <p>1）制作网联格式数字信封,对称算法为SM4/AES</p>
 * <p>2）制作网联格式数字信封,对称算法为DES/3DES/RC2/RC4</p>
 * <p>3）制作网联格式数字信封,使用证书SN</p>
 * <p>4）制作网联格式数字信封,使用证书BankCode</p>
 * <p>5）制作网联格式数字信封,使用证书BankCode，BankCode处于黑名单</p>
 * <p>6）制作网联格式数字信封,原文为空</p>
 * <p>7）制作网联格式数字信封,对称算法为空或null</p>
 * <p>8）制作网联格式数字信封,证书为空或null</p>
 * <p>9）制作网联格式数字信封,证书DN不存在</p>
 * <p>10）制作网联格式数字信封,对称算法为sm4/aes</p>
 * <p>11）制作网联格式数字信封,对称算法错误</p>
 */
@Test(groups = "abcjew.encryptwanglianenvelope")
public class TestEncryptWangLianEnvelope {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;

    NetSignServerInit init = new NetSignServerInit();
    UpkiAgent agent;
    SFTPFile tmp = new SFTPFile();

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
        tmp.downFile(sftp_user, host, sftp_port, sftp_password, ParameterUtil.sftpdetailpath,
                ParameterUtil.localdetailpath);
    }

    /**
     * 制作网联格式数字信封,对称算法为SM4/AES
     *
     * @param sCertDN 证书DN
     * @param sAlg    对称算法
     */
    @Test(groups = "abcjew.encryptwanglianenvelope.normal", dataProvider = "salg-16-alldn", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptWangLianEnvelope_01(String sCertDN, String sAlg) {
        System.out.println("Test EncryptWangLianEnvelope SAlg SM4/AES");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;

        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertDN, sAlg);
            Object bool_result = upkiResult.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result) && upkiResult.getReturnCode() != 0) {
                Assert.fail("制作网联格式数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作网联格式数字信封,对称算法为DES/3DES/RC2/RC4
     *
     * @param sCertDN 证书DN
     * @param sAlg    对称加密算法
     */
    @Test(groups = "abcjew.encryptwanglianenvelope.normal", dataProvider = "salg-8-alldn", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptWangLianEnvelope_02(String sCertDN, String sAlg) {
        System.out.println("Test EncryptWangLianEnvelope SAlg DES/3DES/RC2/RC4");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertDN, sAlg);
            Object bool_result = upkiResult.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"false".equals(bool_result) && upkiResult.getReturnCode() != -100112) {
                Assert.fail("制作网联格式数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作网联格式数字信封,使用证书SN
     *
     * @param sCertSN 证书SN
     * @param sAlg    对称算法
     */
    @Test(groups = "abcjew.encryptwanglianenvelope.normal", dataProvider = "salg-16-allsn", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptWangLianEnvelope_03(String sCertSN, String sAlg) {
        System.out.println("Test EncryptWangLianEnvelope sCertSN Normal");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;

        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertSN, sAlg);
            Object bool_result = upkiResult.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result) && upkiResult.getReturnCode() != 0) {
                Assert.fail("制作网联格式数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作网联格式数字信封,使用证书BankCode
     *
     * @param sCertBankCode 证书BankCode
     * @param sAlg          对称算法
     */
    @Test(groups = "abcjew.encryptwanglianenvelope.normal", dataProvider = "salg-16-allbankcode", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptWangLianEnvelope_04(String sCertBankCode, String sAlg) {
        System.out.println("Test EncryptWangLianEnvelope BankCode Normal");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        if ("10year".equals(sCertBankCode)) {
            return;
        }
        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertBankCode, sAlg);
            Object bool_result = upkiResult.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result) && upkiResult.getReturnCode() != 0) {
                Assert.fail("制作网联格式数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作网联格式数字信封,使用证书BankCode，BankCode处于黑名单
     *
     * @param sCertBankCode 证书BankCode
     * @param sAlg          对称算法
     */
    @Test(groups = "abcjew.encryptwanglianenvelope.normal")
    public void testEncryptWangLianEnvelope_05() {
        System.out.println("Test EncryptWangLianEnvelope BankCode Normal");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String sCertBankCode = "10year";
        String sAlg = "SM4";
        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertBankCode, sAlg);
            if (upkiResult.getReturnCode() != -100226) {
                Assert.fail("制作网联格式数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作网联格式数字信封,原文为空
     *
     * @param sCertDN 证书DN
     * @param sAlg    对称算法
     */
    @Test(groups = "abcjew.encryptwanglianenvelope.normal", dataProvider = "salg-16-alldn", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptWangLianEnvelope_06(String sCertDN, String sAlg) {
        System.out.println("Test EncryptWangLianEnvelope PlainText Null");

        UpkiResult upkiResult;
        try {
            upkiResult = agent.encryptWangLianEnvelope(null, sCertDN, sAlg);
            if (upkiResult.getReturnCode() != -1026) {
                Assert.fail("制作网联格式数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作网联格式数字信封,对称算法为空或null
     *
     * @param sAlg    对称算法
     */
    @Test(groups = "abcjew.encryptwanglianenvelope.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptWangLianEnvelope_07(String sAlg) {
        System.out.println("Test EncryptWangLianEnvelope SAlg Empty or Null");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String sCertDN = "CN=c020crlfbdIssueModeHTTP";
        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertDN, sAlg);
            if (upkiResult.getReturnCode() != -100112) {
                Assert.fail("制作网联格式数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作网联格式数字信封,证书为空或null
     *
     * @param sCertDN 证书DN
     */
    @Test(groups = "abcjew.encryptwanglianenvelope.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptWangLianEnvelope_08(String sCertDN) {
        System.out.println("Test EncryptWangLianEnvelope sCertDN Empty or Null");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertDN, sAlg);
            if (upkiResult.getReturnCode() != -100112) {
                if (upkiResult.getReturnCode() != 0) {
                    Assert.fail("制作网联格式数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("制作网联格式数字信封（encryptWangLianEnvelope）：证书DN传入为null或空字符时可以制作网联格式数字信封");
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作网联格式数字信封,证书DN不存在
     *
     */
    @Test(groups = "abcjew.encryptwanglianenvelope.normal")
    public void testEncryptWangLianEnvelope_09() {
        System.out.println("Test EncryptWangLianEnvelope sCertDN Error");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String sCertDN = "CN=123";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertDN, sAlg);
            if (upkiResult.getReturnCode() != -100224) {
                Assert.fail("制作网联格式数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }
    /**
     * 制作网联格式数字信封,对称算法为sm4/aes
     *
     * @param sCertDN 证书DN
     * @param sAlg    对称算法
     */
    @Test(groups = "abcjew.encryptwanglianenvelope.normal", dataProvider = "salg-16-alldn", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptWangLianEnvelope_10(String sCertDN, String sAlg) {
        System.out.println("Test EncryptWangLianEnvelope SAlg sm4/aes");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;

        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertDN, sAlg.toLowerCase());
            Object bool_result = upkiResult.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result) && upkiResult.getReturnCode() != 0) {
                Assert.fail("制作网联格式数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }
    /**
     * 制作网联格式数字信封,对称算法错误
     *
     */
    @Test(groups = "abcjew.encryptwanglianenvelope.normal")
    public void testEncryptWangLianEnvelope_11() {
        System.out.println("Test EncryptWangLianEnvelope sAlg Error");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String sCertDN = "CN=c020crlfbdIssueModeHTTP";
        String sAlg = "ABC";
        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertDN, sAlg);
            if (upkiResult.getReturnCode() != -100112) {
                Assert.fail("制作网联格式数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }
}
